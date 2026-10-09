// Copyright 2026 The Operator-SDK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package openshifttls implements the OpenShift-specific centralized TLS
// security profile support required by OCPSTRAT-2611: it reads the TLS
// profile configured in the cluster's apiservers.config.openshift.io/cluster
// resource and applies it to the helm-operator's metrics server, then
// watches for profile changes and triggers a graceful restart to pick them
// up. This package is downstream-only (never proposed upstream) and wires
// itself into the generic run.ClusterTLSPolicy extension point via a blank
// import of this package from cmd/helm-operator/main.go.
package openshifttls

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	apimachruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/operator-framework/operator-sdk/internal/cmd/helm-operator/run"
)

var log = logf.Log.WithName("openshifttls")

// clusterTLSPolicy implements run.ClusterTLSPolicy by reading the TLS
// security profile from the cluster's APIServer resource and applying it to
// the manager's metrics server TLS configuration.
type clusterTLSPolicy struct {
	// initialProfile is the profile observed in Apply for future comparison in Watch.
	initialProfile configv1.TLSProfileSpec

	// profileSourceAvailable records whether Apply successfully fetched the
	// profile from a live APIServer object or not
	profileSourceAvailable bool

	// fakeClient for unit testing
	fakeClient func(cfg *rest.Config, options ctrlclient.Options) (ctrlclient.Client, error)
}

// New returns the OpenShift ClusterTLSPolicy implementation that enforces
// the cluster's centralized TLS security profile
func New() run.ClusterTLSPolicy {
	return &clusterTLSPolicy{}
}

// newClient returns p.fakeClient if set or ctrlclient.New
func (p *clusterTLSPolicy) newClient() func(*rest.Config, ctrlclient.Options) (ctrlclient.Client, error) {
	if p.fakeClient != nil {
		return p.fakeClient
	}
	return ctrlclient.New
}

// Apply fetches the cluster's TLS security profile and appends the
// corresponding TLS configuration to options.Metrics.TLSOpts.
// any failure other than client construction is just logged
func (p *clusterTLSPolicy) Apply(ctx context.Context, cfg *rest.Config, options manager.Options) (manager.Options, error) {
	scheme := options.Scheme
	if scheme == nil {
		scheme = apimachruntime.NewScheme()
	}
	if err := configv1.AddToScheme(scheme); err != nil {
		return options, fmt.Errorf("failed to register config.openshift.io/v1 scheme: %w", err)
	}
	options.Scheme = scheme

	k8sClient, err := p.newClient()(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return options, fmt.Errorf("failed to create client for cluster TLS profile lookup: %w", err)
	}

	profile, err := tlspkg.FetchAPIServerTLSProfile(ctx, k8sClient)
	if err != nil {
		p.profileSourceAvailable = false
		profile, err = tlspkg.GetTLSProfileSpec(nil)
		if err != nil {
			return options, fmt.Errorf("failed to get default TLS profile: %w", err)
		}
		log.Error(err, "Unable to fetch TLS profile from APIServer (not running on OpenShift, or APIServer/cluster object missing?); falling back to default TLS profile")
	} else {
		p.profileSourceAvailable = true
	}

	p.initialProfile = profile

	tlsConfigFunc, unsupported := tlspkg.NewTLSConfigFromProfile(profile)
	if len(unsupported) > 0 {
		log.Info("Cluster TLS profile references ciphers/groups unsupported by this Go runtime; they will be ignored",
			"unsupported", unsupported)
	}

	options.Metrics.TLSOpts = append(options.Metrics.TLSOpts, tlsConfigFunc)
	log.Info("Applied cluster TLS security profile to metrics server",
		"minTLSVersion", profile.MinTLSVersion, "ciphers", profile.Ciphers)

	return options, nil
}

// Watch registers a SecurityProfileWatcher that cancels ctx (triggering a
// graceful manager shutdown, followed by a container restart that re-fetches
// the profile) whenever the cluster's TLS profile changes.
// no-op if the profile source is not available

func (p *clusterTLSPolicy) WatchIfProfileAvailable(ctx context.Context, mgr manager.Manager, cancel context.CancelFunc) error {
	if !p.profileSourceAvailable {
		log.Info("Cluster TLS security profile was not read from a live APIServer object at startup; " +
			"skipping profile-change watch to avoid stalling on a missing config.openshift.io/apiservers resource")
		return nil
	}

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                mgr.GetClient(),
		InitialTLSProfileSpec: p.initialProfile,
		OnProfileChange: func(_ context.Context, oldProfile, newProfile configv1.TLSProfileSpec) {
			log.Info("Cluster TLS security profile changed; triggering a graceful restart to apply it",
				"old", oldProfile, "new", newProfile)
			cancel()
		},
	}
	return watcher.SetupWithManager(mgr)
}
