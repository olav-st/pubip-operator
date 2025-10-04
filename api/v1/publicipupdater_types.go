/*
Copyright 2025 Olav Sortland Thoresen

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

package v1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PublicIPUpdaterSpec defines the desired state of PublicIPUpdater
type PublicIPUpdaterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	Sources      []string        `json:"sources,omitempty"`
	Targets      []FieldSelector `json:"targets,omitempty"`
	NodeSelector v1.NodeSelector `json:"nodeSelector,omitempty"`
}

// PublicIPUpdaterStatus defines the observed state of PublicIPUpdater.
type PublicIPUpdaterStatus struct {
	// CurrentIP is the currently discovered public IP address
	// +optional
	CurrentIP string `json:"currentIP,omitempty"`

	// LastUpdated is the timestamp when the IP was last successfully updated
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// TargetStatuses contains the status of each target update
	// +optional
	TargetStatuses []TargetStatus `json:"targetStatuses,omitempty"`

	// Conditions represent the latest available observations of the updater's state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// TargetStatus represents the status of updating a specific target field.
type TargetStatus struct {
	// Target reference to the object and field being updated
	Target FieldSelector `json:"target"`

	// LastUpdated is when this target was last updated
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// Status indicates the current status of this target update
	// +kubebuilder:validation:Enum=Success;Failed;Pending
	Status string `json:"status"`

	// Message provides additional details about the target update status
	// +optional
	Message string `json:"message,omitempty"`

	// UpdatedValue is the value that was set in the target field
	// +optional
	UpdatedValue string `json:"updatedValue,omitempty"`
}

// FieldSelector references a specific field in a Kubernetes object.
type FieldSelector struct {
	// ObjectReference identifies the target Kubernetes object
	v1.ObjectReference `json:",inline"`

	// FieldPath specifies the JSON path to the field to update
	FieldPath string `json:"fieldPath"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PublicIPUpdater is the Schema for the publicipupdaters API
type PublicIPUpdater struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of PublicIPUpdater
	// +required
	Spec PublicIPUpdaterSpec `json:"spec"`

	// status defines the observed state of PublicIPUpdater
	// +optional
	Status PublicIPUpdaterStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// PublicIPUpdaterList contains a list of PublicIPUpdater
type PublicIPUpdaterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PublicIPUpdater `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PublicIPUpdater{}, &PublicIPUpdaterList{})
}
