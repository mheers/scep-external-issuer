/*
Copyright 2022 Marcel Heers.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SCEPIssuerSpec defines the desired state of Issuer
type SCEPIssuerSpec struct {
	// URL is the base URL for the endpoint of the signing service,
	// for example: "https://sample-signer.example.com/api".
	URL string `json:"url"`

	// A reference to a Secret in the same namespace as the referent. If the
	// referent is a ClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	AuthSecretName string `json:"authSecretName"`
}

// SCEPIssuerStatus defines the observed state of Issuer
type SCEPIssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Status `json:",inline"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// SCEPIssuer is the Schema for the issuers API
type SCEPIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SCEPIssuerSpec   `json:"spec,omitempty"`
	Status SCEPIssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SCEPIssuerList contains a list of Issuer
type SCEPIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SCEPIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SCEPIssuer{}, &SCEPIssuerList{})
}
