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

package portals

import (
	"context"

	pb "github.com/gke-labs/service-portals/pkg/portals/proto"
)

type ConfiguratorServer struct {
	pb.UnimplementedSidecarReconfiguratorServer
	router *RuleRouter
}

func NewConfiguratorServer(router *RuleRouter) *ConfiguratorServer {
	return &ConfiguratorServer{
		router: router,
	}
}

func protoToRule(p *pb.PortalRule) PortalRule {
	r := PortalRule{
		APIVersion: p.ApiVersion,
		Kind:       p.Kind,
	}
	if p.Metadata != nil {
		r.Metadata.Name = p.Metadata.Name
	}
	if p.Spec != nil {
		r.Spec = RuleSpec{
			Host:       p.Spec.Host,
			RewriteURL: p.Spec.RewriteUrl,
			AuthToken:  p.Spec.AuthToken,
			AuthHeader: p.Spec.AuthHeader,
			CacheTTL:   p.Spec.CacheTtl,
		}
	}
	return r
}

func ruleToProto(r PortalRule) *pb.PortalRule {
	p := &pb.PortalRule{
		ApiVersion: r.APIVersion,
		Kind:       r.Kind,
		Metadata: &pb.Metadata{
			Name: r.Metadata.Name,
		},
		Spec: &pb.RuleSpec{
			Host:       r.Spec.Host,
			RewriteUrl: r.Spec.RewriteURL,
			AuthToken:  r.Spec.AuthToken,
			AuthHeader: r.Spec.AuthHeader,
			CacheTtl:   r.Spec.CacheTTL,
		},
	}
	return p
}

func protoToPolicy(p *pb.SecurityPolicy) *SecurityPolicy {
	if p == nil {
		return nil
	}
	return &SecurityPolicy{
		BlockExec:     p.BlockExec,
		AllowedImages: p.AllowedImages,
	}
}

func policyToProto(p *SecurityPolicy) *pb.SecurityPolicy {
	if p == nil {
		return nil
	}
	return &pb.SecurityPolicy{
		BlockExec:     p.BlockExec,
		AllowedImages: p.AllowedImages,
	}
}

func (s *ConfiguratorServer) UpdateRules(ctx context.Context, req *pb.UpdateRulesRequest) (*pb.UpdateRulesResponse, error) {
	var rules []PortalRule
	for _, pr := range req.GetRules() {
		rules = append(rules, protoToRule(pr))
	}

	if err := s.router.UpdateDynamicRules(rules); err != nil {
		return &pb.UpdateRulesResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.UpdateRulesResponse{
		Success: true,
		Message: "Rules successfully updated",
	}, nil
}

func (s *ConfiguratorServer) ListRules(ctx context.Context, req *pb.ListRulesRequest) (*pb.ListRulesResponse, error) {
	rules := s.router.GetDynamicRules()
	var pbRules []*pb.PortalRule
	for _, r := range rules {
		pbRules = append(pbRules, ruleToProto(r))
	}
	return &pb.ListRulesResponse{
		Rules: pbRules,
	}, nil
}

func (s *ConfiguratorServer) SetSecurityPolicy(ctx context.Context, req *pb.SetSecurityPolicyRequest) (*pb.SetSecurityPolicyResponse, error) {
	policy := protoToPolicy(req.GetPolicy())
	s.router.SetSecurityPolicy(policy)
	return &pb.SetSecurityPolicyResponse{
		Success: true,
		Message: "Security policy set",
	}, nil
}

func (s *ConfiguratorServer) GetSecurityPolicy(ctx context.Context, req *pb.GetSecurityPolicyRequest) (*pb.GetSecurityPolicyResponse, error) {
	policy := s.router.GetSecurityPolicy()
	return &pb.GetSecurityPolicyResponse{
		Policy: policyToProto(policy),
	}, nil
}
