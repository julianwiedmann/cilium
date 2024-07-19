//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package models

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RemoteClusterConfig) DeepCopyInto(out *RemoteClusterConfig) {
	*out = *in
	if in.ServiceExportsEnabled != nil {
		in, out := &in.ServiceExportsEnabled, &out.ServiceExportsEnabled
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RemoteClusterConfig.
func (in *RemoteClusterConfig) DeepCopy() *RemoteClusterConfig {
	if in == nil {
		return nil
	}
	out := new(RemoteClusterConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RemoteClusterSynced) DeepCopyInto(out *RemoteClusterSynced) {
	*out = *in
	if in.ServiceExports != nil {
		in, out := &in.ServiceExports, &out.ServiceExports
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RemoteClusterSynced.
func (in *RemoteClusterSynced) DeepCopy() *RemoteClusterSynced {
	if in == nil {
		return nil
	}
	out := new(RemoteClusterSynced)
	in.DeepCopyInto(out)
	return out
}