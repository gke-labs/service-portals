// Copyright 2026 Google LLC
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

package injector

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HandleMutate handles mutating admission webhook HTTP requests.
func (inj *Injector) HandleMutate(w http.ResponseWriter, r *http.Request) {
	inj.handleAdmission(w, r, func(r *http.Request, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
		return inj.Mutate(r.Context(), req)
	})
}

// HandleValidate handles validating admission webhook HTTP requests.
func (inj *Injector) HandleValidate(w http.ResponseWriter, r *http.Request) {
	inj.handleAdmission(w, r, func(r *http.Request, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
		return inj.Validate(r.Context(), req)
	})
}

func (inj *Injector) handleAdmission(w http.ResponseWriter, r *http.Request, fn func(r *http.Request, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse) {
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method, expected POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "could not parse admission review", http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "empty admission review request", http.StatusBadRequest)
		return
	}

	responseReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: fn(r, review.Request),
	}
	responseReview.Response.UID = review.Request.UID

	respBytes, err := json.Marshal(responseReview)
	if err != nil {
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBytes); err != nil {
		log.Printf("Failed to write admission response: %v", err)
	}
}
