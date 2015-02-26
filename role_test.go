package main

import "testing"

func TestNewRoleARN(t *testing.T) {
	tests := []struct {
		arn  string
		path string
		role string
		ok   bool
	}{
		{arn: "arn:aws:iam::123fail:role:fail", ok: false},
		{arn: "arn:aws:iam::fail123:role:fail", ok: false},
		{arn: "arn:aws:iam::faifail:role:fail", ok: false},
		{arn: "arn:aws:iam::12345:role:fail", ok: false},
		{arn: "arn:aws:iam::12345:role/testpath:fail", ok: false},
		{arn: "arn:aws:iam::12345:role/testrole1", path: "/", role: "testrole1", ok: true},
		{arn: "arn:aws:iam::12345:role/testpath/testrole2", path: "/testpath/", role: "testrole2", ok: true},
	}

	for _, test := range tests {
		r, err := NewRoleARN(test.arn)
		if err != nil {
			if test.ok {
				t.Errorf("Failed evaluating regexp on '%s'", test.arn)
			}
			continue
		}
		if r.Path != test.path {
			t.Errorf("Wanted path '%s' got '%s'", test.path, r.Path)
		}
		if r.Name != test.role {
			t.Errorf("Wanted role '%s' got '%s'", test.role, r.Name)
		}
	}
}
