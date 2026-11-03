package webserver

import "testing"

func TestServiceExecutableMatchesTarget(t *testing.T) {
	tests := []struct {
		name      string
		service   string
		target    string
		wantMatch bool
	}{
		{
			name:      "同一实例忽略大小写和分隔符",
			service:   `G:\soft\nginx-1.26.3\nginx.exe`,
			target:    `g:/soft/nginx-1.26.3/nginx.exe`,
			wantMatch: true,
		},
		{
			name:      "不同安装目录不得匹配",
			service:   `D:\Sanpin\jk\ui\nginx.exe`,
			target:    `G:\soft\nginx-1.26.3\nginx.exe`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serviceExecutableMatchesTarget(tt.service, tt.target); got != tt.wantMatch {
				t.Fatalf("serviceExecutableMatchesTarget(%q, %q) = %v, want %v",
					tt.service, tt.target, got, tt.wantMatch)
			}
		})
	}
}
