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
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pubipv1 "olav.ninja/pubip-operator/api/v1"
)

var _ = Describe("PublicIPUpdater Controller", func() {
	Context("When reconciling a PublicIPUpdater resource", func() {
		const (
			resourceName = "test-publicipupdater"
			namespace    = "default"
			timeout      = time.Second * 30
			interval     = time.Millisecond * 250
		)

		ctx := context.Background()

		var (
			testLogContent map[string]string
			testLogMutex   sync.RWMutex // Add this
		)

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		createTestReconciler := func() *PublicIPUpdaterReconciler {
			return &PublicIPUpdaterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				LogRetriever: func(ctx context.Context, job *batchv1.Job) (string, error) {
					testLogMutex.RLock()
					logs, ok := testLogContent[job.Name]
					testLogMutex.RUnlock()
					if !ok {
						return "", fmt.Errorf("no mock logs for job %s", job.Name)
					}
					return logs, nil
				},
			}
		}

		BeforeEach(func() {
			testLogContent = make(map[string]string)

			By("Creating the custom resource for the Kind PublicIPUpdater")

			publicipupdater := &pubipv1.PublicIPUpdater{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: pubipv1.PublicIPUpdaterSpec{
					Sources: []string{
						"aws_checkip",
						"ipify",
					},
					Targets: []pubipv1.FieldSelector{
						{
							ObjectReference: corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "ConfigMap",
								Name:       "test-config",
								Namespace:  namespace,
							},
							FieldPath: "data.publicIP",
						},
					},
					NodeSelector: corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/os",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"linux"},
									},
								},
							},
						},
					},
				},
			}

			err := k8sClient.Get(ctx, typeNamespacedName, publicipupdater)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, publicipupdater)).To(Succeed())
			}

			// Create the target ConfigMap
			targetConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: namespace,
				},
				Data: map[string]string{
					"publicIP": "",
				},
			}

			err = k8sClient.Get(ctx, types.NamespacedName{Name: "test-config", Namespace: namespace}, targetConfigMap)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, targetConfigMap)).To(Succeed())
			}

			// Start a goroutine to automatically complete any Jobs created during tests
			// This simulates the Job execution that won't happen in envtest
			go func() {
				defer GinkgoRecover()
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				timeout := time.After(10 * time.Minute)

				for {
					select {
					case <-timeout:
						GinkgoWriter.Println("Mock goroutine timed out")
						return
					case <-ticker.C:
						jobList := &batchv1.JobList{}
						err := k8sClient.List(ctx, jobList,
							client.InNamespace(namespace),
							client.HasLabels{"pubip.olav.ninja/updater"})

						if err != nil {
							GinkgoWriter.Printf("Error listing jobs: %v\n", err)
							continue
						}

						for i := range jobList.Items {
							job := &jobList.Items[i]

							if job.Status.Succeeded > 0 || job.Status.Failed > 0 {
								continue
							}

							// Create pod
							podName := job.Name + "-pod"
							pod := &corev1.Pod{
								ObjectMeta: metav1.ObjectMeta{
									Name:      podName,
									Namespace: namespace,
									Labels:    map[string]string{"job-name": job.Name},
								},
								Spec: corev1.PodSpec{
									Containers:    []corev1.Container{{Name: "ip-fetcher", Image: "test"}},
									RestartPolicy: corev1.RestartPolicyNever,
								},
							}

							err = k8sClient.Create(ctx, pod)
							if err != nil && !errors.IsAlreadyExists(err) {
								GinkgoWriter.Printf("Error creating pod: %v\n", err)
								continue
							}
							pod.Status.Phase = corev1.PodSucceeded
							err = k8sClient.Status().Update(ctx, pod)
							if err != nil {
								GinkgoWriter.Printf("Error updating pod status: %v\n", err)
								continue
							}

							testLogMutex.Lock()
							testLogContent[job.Name] = "1.2.3.4"
							testLogMutex.Unlock()

							job.Status.Succeeded = 1
							job.Status.CompletionTime = &metav1.Time{Time: time.Now()}
							job.Status.Conditions = []batchv1.JobCondition{
								{Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
									LastTransitionTime: metav1.Now()},
							}
							err = k8sClient.Status().Update(ctx, job)
							if err != nil {
								GinkgoWriter.Printf("Error updating job status: %v\n", err)
								continue
							}
						}
					}
				}
			}()
		})

		AfterEach(func() {
			By("Cleanup the specific resource instance PublicIPUpdater")
			resource := &pubipv1.PublicIPUpdater{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}

			By("Cleanup the test ConfigMap")
			configMap := &corev1.ConfigMap{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "test-config", Namespace: namespace}, configMap)
			if err == nil {
				Expect(k8sClient.Delete(ctx, configMap)).To(Succeed())
			}

			By("Cleanup all jobs in the namespace")
			jobList := &batchv1.JobList{}
			err = k8sClient.List(ctx, jobList, client.InNamespace(namespace))
			if err == nil {
				for i := range jobList.Items {
					job := &jobList.Items[i]
					Expect(k8sClient.Delete(ctx, job)).To(Succeed())
				}
			}

			By("Cleanup all pods in the namespace")
			podList := &corev1.PodList{}
			err = k8sClient.List(ctx, podList, client.InNamespace(namespace))
			if err == nil {
				for i := range podList.Items {
					pod := &podList.Items[i]
					Expect(k8sClient.Delete(ctx, pod)).To(Succeed())
				}
			}
		})

		It("should successfully reconcile the resource", func() {
			controllerReconciler := createTestReconciler()
			controllerReconciler.UpdateInterval = DefaultUpdateInterval

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that the status is updated")
			Eventually(func() bool {
				updater := &pubipv1.PublicIPUpdater{}
				err := k8sClient.Get(ctx, typeNamespacedName, updater)
				if err != nil {
					return false
				}
				return updater.Status.LastUpdated != nil
			}, timeout, interval).Should(BeTrue())
		})

		It("should create a job for IP discovery using the custom fetcher", func() {
			By("Reconciling the resource")
			controllerReconciler := createTestReconciler()

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that a job is created")
			Eventually(func() bool {
				jobList := &batchv1.JobList{}
				err := k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": resourceName})
				return err == nil && len(jobList.Items) > 0
			}, timeout, interval).Should(BeTrue())

			By("Verifying job configuration")
			jobList := &batchv1.JobList{}
			err = k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": resourceName})
			Expect(err).NotTo(HaveOccurred())
			Expect(jobList.Items).ToNot(BeEmpty())

			job := jobList.Items[0]
			Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))
			container := job.Spec.Template.Spec.Containers[0]
			Expect(container.Image).To(Equal(DefaultFetcherImage))
			Expect(container.Args).To(ContainElement("--sources"))
			Expect(container.Args).To(ContainElement("aws_checkip,ipify"))
			Expect(container.Args).To(ContainElement("--strategy"))
			Expect(container.Args).To(ContainElement("first"))
			Expect(container.Args).To(ContainElement("--address-family"))
			Expect(container.Args).To(ContainElement("ipv4"))
			Expect(container.Args).To(ContainElement("--format"))
			Expect(container.Args).To(ContainElement("plain"))
		})

		It("should handle multiple sources in simplified format", func() {
			By("Creating a PublicIPUpdater with multiple sources")
			multiSourceUpdater := &pubipv1.PublicIPUpdater{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-source-updater",
					Namespace: namespace,
				},
				Spec: pubipv1.PublicIPUpdaterSpec{
					Sources: []string{
						"aws_checkip",
						"ipify",
						"ipinfo",
					},
					Targets: []pubipv1.FieldSelector{
						{
							ObjectReference: corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "ConfigMap",
								Name:       "test-config",
								Namespace:  namespace,
							},
							FieldPath: "data.publicIP",
						},
					},
					NodeSelector: corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-type",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"worker"},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, multiSourceUpdater)).To(Succeed())

			defer func() {
				Expect(k8sClient.Delete(ctx, multiSourceUpdater)).To(Succeed())
			}()

			By("Reconciling the multi-source updater")
			controllerReconciler := createTestReconciler()
			controllerReconciler.UpdateInterval = DefaultUpdateInterval

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "multi-source-updater",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that a job is created with all sources")
			Eventually(func() bool {
				jobList := &batchv1.JobList{}
				err := k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": "multi-source-updater"})
				if err != nil || len(jobList.Items) == 0 {
					return false
				}

				job := jobList.Items[0]
				container := job.Spec.Template.Spec.Containers[0]
				return containsArg(container.Args, "--sources", "aws_checkip,ipify,ipinfo")
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle custom node selector", func() {
			By("Creating a PublicIPUpdater with custom node selector")
			customNodeUpdater := &pubipv1.PublicIPUpdater{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-node-updater",
					Namespace: namespace,
				},
				Spec: pubipv1.PublicIPUpdaterSpec{
					Sources: []string{"ipify"},
					Targets: []pubipv1.FieldSelector{
						{
							ObjectReference: corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "ConfigMap",
								Name:       "test-config",
								Namespace:  namespace,
							},
							FieldPath: "data.publicIP",
						},
					},
					NodeSelector: corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-type",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"worker"},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, customNodeUpdater)).To(Succeed())

			defer func() {
				Expect(k8sClient.Delete(ctx, customNodeUpdater)).To(Succeed())
			}()

			By("Reconciling the updater with custom node selector")
			controllerReconciler := createTestReconciler()
			controllerReconciler.UpdateInterval = DefaultUpdateInterval

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "custom-node-updater",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that the job has the correct node selector")
			Eventually(func() bool {
				jobList := &batchv1.JobList{}
				err := k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": "custom-node-updater"})
				if err != nil || len(jobList.Items) == 0 {
					return false
				}

				job := jobList.Items[0]
				nodeSelector := job.Spec.Template.Spec.NodeSelector
				return nodeSelector != nil && nodeSelector["node-type"] == "worker"
			}, timeout, interval).Should(BeTrue())
		})

		It("should update conditions correctly", func() {
			By("Reconciling the resource")
			controllerReconciler := createTestReconciler()

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that conditions are set")
			Eventually(func() bool {
				updater := &pubipv1.PublicIPUpdater{}
				err := k8sClient.Get(ctx, typeNamespacedName, updater)
				if err != nil {
					return false
				}
				return len(updater.Status.Conditions) > 0
			}, timeout, interval).Should(BeTrue())

			By("Verifying condition types")
			updater := &pubipv1.PublicIPUpdater{}
			err = k8sClient.Get(ctx, typeNamespacedName, updater)
			Expect(err).NotTo(HaveOccurred())

			conditionTypes := make(map[string]bool)
			for _, condition := range updater.Status.Conditions {
				conditionTypes[condition.Type] = true
			}

			// We expect at least one condition to be set
			Expect(conditionTypes).ToNot(BeEmpty())
		})

		It("should handle missing sources gracefully", func() {
			By("Creating a PublicIPUpdater with no sources")
			noSourceUpdater := &pubipv1.PublicIPUpdater{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-source-updater",
					Namespace: namespace,
				},
				Spec: pubipv1.PublicIPUpdaterSpec{
					Sources: []string{}, // Empty sources
					Targets: []pubipv1.FieldSelector{
						{
							ObjectReference: corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "ConfigMap",
								Name:       "test-config",
								Namespace:  namespace,
							},
							FieldPath: "data.publicIP",
						},
					},
					NodeSelector: corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-type",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"worker"},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, noSourceUpdater)).To(Succeed())

			defer func() {
				Expect(k8sClient.Delete(ctx, noSourceUpdater)).To(Succeed())
			}()

			By("Reconciling the updater with no sources")
			controllerReconciler := createTestReconciler()
			controllerReconciler.UpdateInterval = DefaultUpdateInterval

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "no-source-updater",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that appropriate conditions are set")
			Eventually(func() bool {
				updater := &pubipv1.PublicIPUpdater{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: "no-source-updater", Namespace: namespace}, updater)
				if err != nil {
					return false
				}

				for _, condition := range updater.Status.Conditions {
					if condition.Type == ConditionTypeIPDiscovered && condition.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("should respect update intervals", func() {
			By("Creating a recently updated PublicIPUpdater")
			recentUpdater := &pubipv1.PublicIPUpdater{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "recent-updater",
					Namespace: namespace,
				},
				Spec: pubipv1.PublicIPUpdaterSpec{
					Sources: []string{"ipify"},
					Targets: []pubipv1.FieldSelector{
						{
							ObjectReference: corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "ConfigMap",
								Name:       "test-config",
								Namespace:  namespace,
							},
							FieldPath: "data.publicIP",
						},
					},
					NodeSelector: corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-type",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"worker"},
									},
								},
							},
						},
					},
				},
				Status: pubipv1.PublicIPUpdaterStatus{
					LastUpdated: &metav1.Time{Time: time.Now()}, // Just updated
					CurrentIP:   "1.2.3.4",
				},
			}

			Expect(k8sClient.Create(ctx, recentUpdater)).To(Succeed())

			recentUpdater.Status.LastUpdated = &metav1.Time{Time: time.Now()}
			recentUpdater.Status.CurrentIP = "1.2.3.4"
			Expect(k8sClient.Status().Update(ctx, recentUpdater)).To(Succeed())

			defer func() {
				Expect(k8sClient.Delete(ctx, recentUpdater)).To(Succeed())
			}()

			By("Reconciling the recently updated resource")
			controllerReconciler := createTestReconciler()
			controllerReconciler.UpdateInterval = DefaultUpdateInterval

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "recent-updater",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that it's requeued for later")
			Expect(result.RequeueAfter).To(Equal(DefaultUpdateInterval))

			By("Verifying no new jobs were created")
			jobList := &batchv1.JobList{}
			err = k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": "recent-updater"})
			Expect(err).NotTo(HaveOccurred())
			Expect(jobList.Items).To(BeEmpty())
		})

		It("should handle job with correct resource limits", func() {
			By("Reconciling the resource")
			controllerReconciler := createTestReconciler()

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that the job has correct resource limits")
			Eventually(func() bool {
				jobList := &batchv1.JobList{}
				err := k8sClient.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"pubip.olav.ninja/updater": resourceName})
				if err != nil || len(jobList.Items) == 0 {
					return false
				}

				job := jobList.Items[0]
				container := job.Spec.Template.Spec.Containers[0]

				// Check resource requests and limits
				requests := container.Resources.Requests
				limits := container.Resources.Limits

				return requests != nil && limits != nil &&
					requests.Cpu().String() == "10m" &&
					requests.Memory().String() == "32Mi" &&
					limits.Cpu().String() == "100m" &&
					limits.Memory().String() == "128Mi"
			}, timeout, interval).Should(BeTrue())
		})
	})

	Describe("Helper functions", func() {
		It("shouldUpdateIP should work correctly", func() {
			reconciler := &PublicIPUpdaterReconciler{}

			By("Returning true for first run")
			updater := &pubipv1.PublicIPUpdater{}
			Expect(reconciler.shouldUpdateIP(updater, DefaultUpdateInterval)).To(BeTrue())

			By("Returning false for recent update")
			updater.Status.LastUpdated = &metav1.Time{Time: time.Now()}
			Expect(reconciler.shouldUpdateIP(updater, DefaultUpdateInterval)).To(BeFalse())

			By("Returning true for old update")
			updater.Status.LastUpdated = &metav1.Time{Time: time.Now().Add(-2 * DefaultUpdateInterval)}
			Expect(reconciler.shouldUpdateIP(updater, DefaultUpdateInterval)).To(BeTrue())
		})

		It("updateCondition should work correctly", func() {
			reconciler := &PublicIPUpdaterReconciler{}
			updater := &pubipv1.PublicIPUpdater{
				Status: pubipv1.PublicIPUpdaterStatus{
					Conditions: []metav1.Condition{},
				},
			}

			By("Adding a new condition")
			reconciler.updateCondition(updater, "TestCondition", metav1.ConditionTrue, "TestReason", "Test message")
			Expect(updater.Status.Conditions).To(HaveLen(1))
			Expect(updater.Status.Conditions[0].Type).To(Equal("TestCondition"))
			Expect(updater.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))

			By("Updating existing condition")
			reconciler.updateCondition(updater, "TestCondition", metav1.ConditionFalse, "NewReason", "New message")
			Expect(updater.Status.Conditions).To(HaveLen(1))
			Expect(updater.Status.Conditions[0].Status).To(Equal(metav1.ConditionFalse))
			Expect(updater.Status.Conditions[0].Reason).To(Equal("NewReason"))
		})

		It("buildNodeSelector should work correctly", func() {
			reconciler := &PublicIPUpdaterReconciler{}

			By("Returning nil for empty node selector")
			emptySelector := corev1.NodeSelector{}
			result := reconciler.buildNodeSelector(emptySelector)
			Expect(result).To(BeNil())

			By("Converting node selector correctly")
			nodeSelector := corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"linux"},
							},
							{
								Key:      "node-type",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"worker"},
							},
						},
					},
				},
			}
			result = reconciler.buildNodeSelector(nodeSelector)
			Expect(result).NotTo(BeNil())
			Expect(result["kubernetes.io/os"]).To(Equal("linux"))
			Expect(result["node-type"]).To(Equal("worker"))
		})
	})
})

// Helper function to check if args contain a flag with a specific value
func containsArg(args []string, flag, value string) bool {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}
