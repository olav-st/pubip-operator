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

package controller

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	pubipv1 "olav.ninja/pubip-operator/api/v1"
)

const (
	// DefaultUpdateInterval is the default time between IP checks
	DefaultUpdateInterval = 1 * time.Hour

	// JobTTLSecondsAfterFinished specifies how long to keep completed jobs
	JobTTLSecondsAfterFinished = 3600 // 1 hour

	// ConditionTypeReady indicates the overall readiness of the PublicIPUpdater
	ConditionTypeReady = "Ready"

	// ConditionTypeIPDiscovered indicates successful IP discovery
	ConditionTypeIPDiscovered = "IPDiscovered"

	// ConditionTypeTargetsUpdated indicates successful target updates
	ConditionTypeTargetsUpdated = "TargetsUpdated"

	// DefaultFetcherImage is the default image for the IP fetcher
	DefaultFetcherImage = "ghcr.io/olav-st/pubip-operator-fetcher:v0.0.0"
)

// PublicIPUpdaterReconciler reconciles a PublicIPUpdater object
type PublicIPUpdaterReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Clientset      kubernetes.Interface
	LogRetriever   func(ctx context.Context, job *batchv1.Job) (string, error)
	FetcherImage   string
	UpdateInterval time.Duration
}

// +kubebuilder:rbac:groups=pubip.olav.ninja,resources=publicipupdaters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pubip.olav.ninja,resources=publicipupdaters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pubip.olav.ninja,resources=publicipupdaters/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services;endpoints,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PublicIPUpdaterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PublicIPUpdater instance
	var publicIPUpdater pubipv1.PublicIPUpdater
	if err := r.Get(ctx, req.NamespacedName, &publicIPUpdater); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("PublicIPUpdater resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get PublicIPUpdater")
		return ctrl.Result{}, err
	}

	updateInterval := DefaultUpdateInterval
	if r.UpdateInterval > 0 {
		updateInterval = r.UpdateInterval
	}

	// Check if we need to update the IP
	if !r.shouldUpdateIP(&publicIPUpdater, updateInterval) {
		logger.V(1).Info("IP update not needed yet")
		return ctrl.Result{RequeueAfter: updateInterval}, nil
	}

	// Initialize status if needed
	if publicIPUpdater.Status.Conditions == nil {
		publicIPUpdater.Status.Conditions = []metav1.Condition{}
	}

	// Discover IP using the custom fetcher
	discoveredIP, err := r.discoverPublicIP(ctx, &publicIPUpdater)
	if err != nil {
		logger.Error(err, "Failed to discover public IP")
		r.updateCondition(&publicIPUpdater, ConditionTypeIPDiscovered, metav1.ConditionFalse, "DiscoveryFailed", err.Error())
		r.updateCondition(&publicIPUpdater, ConditionTypeReady, metav1.ConditionFalse, "IPDiscoveryFailed", err.Error())
		return r.updateStatus(ctx, &publicIPUpdater, "", nil, updateInterval)
	}

	// Validate IP address
	if net.ParseIP(discoveredIP) == nil {
		err := fmt.Errorf("invalid IP address discovered: %s", discoveredIP)
		logger.Error(err, "Invalid IP address")
		r.updateCondition(&publicIPUpdater, ConditionTypeIPDiscovered, metav1.ConditionFalse, "InvalidIP", err.Error())
		r.updateCondition(&publicIPUpdater, ConditionTypeReady, metav1.ConditionFalse, "InvalidIP", err.Error())
		return r.updateStatus(ctx, &publicIPUpdater, "", nil, updateInterval)
	}

	logger.Info("Successfully discovered public IP", "ip", discoveredIP)
	r.updateCondition(&publicIPUpdater, ConditionTypeIPDiscovered, metav1.ConditionTrue, "IPDiscovered", fmt.Sprintf("Successfully discovered IP: %s", discoveredIP))

	// Update target fields if IP has changed
	var targetStatuses []pubipv1.TargetStatus
	if discoveredIP != publicIPUpdater.Status.CurrentIP {
		targetStatuses, err = r.updateTargetFields(ctx, &publicIPUpdater, discoveredIP)
		if err != nil {
			logger.Error(err, "Failed to update target fields")
			r.updateCondition(&publicIPUpdater, ConditionTypeTargetsUpdated, metav1.ConditionFalse, "UpdateFailed", err.Error())
			r.updateCondition(&publicIPUpdater, ConditionTypeReady, metav1.ConditionFalse, "TargetUpdateFailed", err.Error())
			return r.updateStatus(ctx, &publicIPUpdater, discoveredIP, targetStatuses, updateInterval)
		}

		logger.Info("Successfully updated target fields", "ip", discoveredIP, "targets", len(targetStatuses))
		r.updateCondition(&publicIPUpdater, ConditionTypeTargetsUpdated, metav1.ConditionTrue, "TargetsUpdated", fmt.Sprintf("Successfully updated %d targets", len(targetStatuses)))
	} else {
		logger.V(1).Info("IP hasn't changed, skipping target updates", "ip", discoveredIP)
		// Copy existing target statuses
		targetStatuses = publicIPUpdater.Status.TargetStatuses
	}

	r.updateCondition(&publicIPUpdater, ConditionTypeReady, metav1.ConditionTrue, "Ready", "PublicIPUpdater is ready and operational")

	// Update status and requeue for next check
	result, err := r.updateStatus(ctx, &publicIPUpdater, discoveredIP, targetStatuses, updateInterval)
	if err != nil {
		return result, err
	}

	return ctrl.Result{RequeueAfter: updateInterval}, nil
}

// shouldUpdateIP determines if we need to check/update the IP
func (r *PublicIPUpdaterReconciler) shouldUpdateIP(updater *pubipv1.PublicIPUpdater, updateInterval time.Duration) bool {
	if updater.Status.LastUpdated == nil {
		return true // First run
	}

	timeSinceLastUpdate := time.Since(updater.Status.LastUpdated.Time)
	return timeSinceLastUpdate >= updateInterval
}

// discoverPublicIP discovers the public IP using the custom Go fetcher application
func (r *PublicIPUpdaterReconciler) discoverPublicIP(ctx context.Context, updater *pubipv1.PublicIPUpdater) (string, error) {
	if len(updater.Spec.Sources) == 0 {
		return "", fmt.Errorf("no IP sources configured")
	}

	// Create a job to run the custom fetcher
	job, err := r.createFetcherJob(ctx, updater)
	if err != nil {
		return "", fmt.Errorf("failed to create fetcher job: %w", err)
	}

	// Wait for job completion and get the IP
	ip, err := r.waitForJobAndGetIP(ctx, job)
	if err != nil {
		return "", fmt.Errorf("failed to wait for job completion: %w", err)
	}

	return ip, nil
}

// createFetcherJob creates a Kubernetes Job to run the custom IP fetcher
func (r *PublicIPUpdaterReconciler) createFetcherJob(ctx context.Context, updater *pubipv1.PublicIPUpdater) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("pubip-operator-fetcher-%s-%d", updater.Name, time.Now().Unix())

	// Build the fetcher command arguments
	args := []string{
		"--sources", strings.Join(updater.Spec.Sources, ","),
		"--strategy", "first", // Use first successful source
		"--address-family", "ipv4",
		"--format", "plain",
	}

	// Use the configured image, fallback to default if not set
	fetcherImage := r.FetcherImage
	if fetcherImage == "" {
		fetcherImage = DefaultFetcherImage
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: updater.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "pubip-operator",
				"app.kubernetes.io/instance":  updater.Name,
				"app.kubernetes.io/component": "ip-fetcher",
				"pubip.olav.ninja/updater":    updater.Name,
				"pubip.olav.ninja/job-type":   "fetcher",
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: int32Ptr(JobTTLSecondsAfterFinished),
			BackoffLimit:            int32Ptr(3),
			CompletionMode:          completionModePtr(batchv1.NonIndexedCompletion),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					NodeSelector:  r.buildNodeSelector(updater.Spec.NodeSelector),
					Containers: []corev1.Container{
						{
							Name:            "ip-fetcher",
							Image:           fetcherImage,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args:            args,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("10m"),
									corev1.ResourceMemory: resource.MustParse("32Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								RunAsNonRoot:             boolPtr(true),
								RunAsUser:                int64Ptr(1000),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(updater, job, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create the job
	if err := r.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
	}

	return job, nil
}

// waitForJobAndGetIP waits for job completion and extracts IP from logs
func (r *PublicIPUpdaterReconciler) waitForJobAndGetIP(ctx context.Context, job *batchv1.Job) (string, error) {
	logger := log.FromContext(ctx)

	// Wait for job completion
	timeout := time.NewTimer(1*time.Minute + 30*time.Second)
	defer timeout.Stop()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			return "", fmt.Errorf("timeout waiting for job completion")
		case <-ticker.C:
			// Check job status
			currentJob := &batchv1.Job{}
			if err := r.Get(ctx, client.ObjectKeyFromObject(job), currentJob); err != nil {
				return "", fmt.Errorf("failed to get job status: %w", err)
			}

			if currentJob.Status.Succeeded > 0 {
				// Job completed successfully, get the logs
				return r.getIPFromJobLogs(ctx, currentJob)
			}

			if currentJob.Status.Failed > 0 {
				// Get logs for debugging
				logs, logErr := r.LogRetriever(ctx, currentJob)
				if logErr != nil {
					return "", fmt.Errorf("job failed and could not retrieve logs: %w", logErr)
				}
				return "", fmt.Errorf("job failed with logs: %s", logs)
			}

			logger.V(1).Info("Waiting for job completion", "job", currentJob.Name)
		}
	}
}

// getIPFromJobLogs extracts IP address from job pod logs
func (r *PublicIPUpdaterReconciler) getIPFromJobLogs(ctx context.Context, job *batchv1.Job) (string, error) {
	logs, err := r.LogRetriever(ctx, job)
	if err != nil {
		return "", err
	}

	logContent := strings.TrimSpace(logs)

	if net.ParseIP(logContent) == nil {
		return "", fmt.Errorf("invalid IP address in logs: %s", logContent)
	}

	return logContent, nil
}

// defaultLogRetriever uses the Kubernetes client to fetch logs from the job's pod
func (r *PublicIPUpdaterReconciler) defaultLogRetriever(ctx context.Context, job *batchv1.Job) (string, error) {
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(job.Namespace), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return "", fmt.Errorf("failed to list job pods: %w", err)
	}

	if len(podList.Items) == 0 {
		return "", fmt.Errorf("no pods found for job")
	}

	pod := podList.Items[0]

	req := r.Clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
	logs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pod logs: %w", err)
	}

	buf := make([]byte, 2048)
	n, err := logs.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read pod logs: %w", err)
	}

	err = logs.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close pod logs stream: %w", err)
	}

	return string(buf[:n]), nil
}

// updateTargetFields updates the specified target fields with the discovered IP
func (r *PublicIPUpdaterReconciler) updateTargetFields(ctx context.Context, updater *pubipv1.PublicIPUpdater, ip string) ([]pubipv1.TargetStatus, error) {
	logger := log.FromContext(ctx)
	targetStatuses := make([]pubipv1.TargetStatus, 0, len(updater.Spec.Targets))

	for _, target := range updater.Spec.Targets {
		status := pubipv1.TargetStatus{
			Target:       target,
			Status:       "Pending",
			LastUpdated:  &metav1.Time{Time: time.Now()},
			UpdatedValue: ip,
		}

		if err := r.updateTargetField(ctx, target, ip); err != nil {
			logger.Error(err, "Failed to update target field", "target", target)
			return nil, err
		}

		logger.Info("Successfully updated target field", "target", target, "ip", ip)
		status.Status = "Success"

		targetStatuses = append(targetStatuses, status)
	}

	return targetStatuses, nil
}

// updateTargetField updates a specific target field
func (r *PublicIPUpdaterReconciler) updateTargetField(ctx context.Context, target pubipv1.FieldSelector, ip string) error {
	// Get the target object
	targetObj := &unstructured.Unstructured{}

	// Parse API version to get group and version
	gv, err := schema.ParseGroupVersion(target.APIVersion)
	if err != nil {
		return fmt.Errorf("failed to parse API version %s: %w", target.APIVersion, err)
	}

	targetObj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    target.Kind,
	})

	objKey := types.NamespacedName{
		Name:      target.Name,
		Namespace: target.Namespace,
	}

	if err := r.Get(ctx, objKey, targetObj); err != nil {
		return fmt.Errorf("failed to get target object: %w", err)
	}

	// Update the field using JSON path
	fieldParts := strings.Split(target.FieldPath, ".")
	if err := unstructured.SetNestedField(targetObj.Object, ip, fieldParts...); err != nil {
		return fmt.Errorf("failed to set field %s: %w", target.FieldPath, err)
	}

	// Update the object
	if err := r.Update(ctx, targetObj); err != nil {
		return fmt.Errorf("failed to update target object: %w", err)
	}

	return nil
}

// buildNodeSelector converts NodeSelector to map for pod spec
func (r *PublicIPUpdaterReconciler) buildNodeSelector(nodeSelector corev1.NodeSelector) map[string]string {
	if len(nodeSelector.NodeSelectorTerms) == 0 {
		return nil
	}

	selector := make(map[string]string)

	// Use the first term for simplicity
	term := nodeSelector.NodeSelectorTerms[0]
	for _, expr := range term.MatchExpressions {
		if expr.Operator == corev1.NodeSelectorOpIn && len(expr.Values) > 0 {
			selector[expr.Key] = expr.Values[0]
		}
	}

	return selector
}

// updateCondition updates or adds a condition to the status
func (r *PublicIPUpdaterReconciler) updateCondition(updater *pubipv1.PublicIPUpdater, conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}

	// Find existing condition
	for i, existing := range updater.Status.Conditions {
		if existing.Type == conditionType {
			if existing.Status != status {
				updater.Status.Conditions[i] = condition
			}
			return
		}
	}

	// Add new condition
	updater.Status.Conditions = append(updater.Status.Conditions, condition)
}

// updateStatus updates the PublicIPUpdater status
func (r *PublicIPUpdaterReconciler) updateStatus(ctx context.Context, updater *pubipv1.PublicIPUpdater, currentIP string, targetStatuses []pubipv1.TargetStatus, updateInterval time.Duration) (ctrl.Result, error) {
	updater.Status.CurrentIP = currentIP
	updater.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	if targetStatuses != nil {
		updater.Status.TargetStatuses = targetStatuses
	}

	if err := r.Status().Update(ctx, updater); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	return ctrl.Result{RequeueAfter: updateInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PublicIPUpdaterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.LogRetriever == nil {
		r.LogRetriever = r.defaultLogRetriever
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&pubipv1.PublicIPUpdater{}).
		Owns(&batchv1.Job{}).
		Named("publicipupdater").
		Complete(r)
}

// Helper functions

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}

func int64Ptr(i int64) *int64 {
	return &i
}

func completionModePtr(mode batchv1.CompletionMode) *batchv1.CompletionMode {
	return &mode
}
