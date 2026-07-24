package main

import "testing"

func TestParseIPListRange(t *testing.T) {
	ips, err := parseIPList("192.168.31.105-192.168.31.110")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 6 {
		t.Fatalf("want 6 got %d", len(ips))
	}
}

func TestCollectTargetsFromTo(t *testing.T) {
	ips, err := collectTargets("", "192.168.31.105", "192.168.31.110")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 6 {
		t.Fatalf("want 6 got %d", len(ips))
	}
}
