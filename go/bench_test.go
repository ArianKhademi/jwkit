package jwkit

import (
	"context"
	"sort"
	"testing"
	"time"
)

// BenchmarkVerifyCached measures Verify on the hot path: the issuer's keys
// are already cached, so there is no network I/O, only parsing, one signature
// verification and the claim checks.
//
// Besides the usual mean (ns/op) it reports the median and 99th percentile of
// the individual call latencies, because a mean hides the tail.
func BenchmarkVerifyCached(b *testing.B) {
	for _, key := range []testKey{rsaKey1, ecKey1} {
		b.Run(key.alg, func(b *testing.B) {
			v := newTestVerifier(b, newFakeIssuer(b, rsaKey1, ecKey1), newFakeClock())
			token := key.token()
			ctx := context.Background()
			if _, err := v.Verify(ctx, token); err != nil { // fetch the JWKS before timing
				b.Fatal(err)
			}

			latencies := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				if _, err := v.Verify(ctx, token); err != nil {
					b.Fatal(err)
				}
				latencies = append(latencies, time.Since(start))
			}
			b.StopTimer()

			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			b.ReportMetric(float64(latencies[len(latencies)/2].Nanoseconds()), "p50-ns")
			b.ReportMetric(float64(latencies[len(latencies)*99/100].Nanoseconds()), "p99-ns")
		})
	}
}

// BenchmarkVerifyCachedParallel is the same hot path under contention, to
// show what the key cache's single mutex costs when every core is verifying.
func BenchmarkVerifyCachedParallel(b *testing.B) {
	v := newTestVerifier(b, newFakeIssuer(b, rsaKey1), newFakeClock())
	token := rsaKey1.token()
	ctx := context.Background()
	if _, err := v.Verify(ctx, token); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Verify(ctx, token); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkReject measures how cheaply bad tokens are turned away. Both are
// rejected before any key lookup or cryptography.
func BenchmarkReject(b *testing.B) {
	v := newTestVerifier(b, newFakeIssuer(b, rsaKey1), newFakeClock())
	ctx := context.Background()
	for name, token := range map[string]string{
		"Malformed": "this.is.not-a-token",
		"AlgNone":   unsigned(map[string]any{"alg": "none", "typ": "JWT"}),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := v.Verify(ctx, token); err == nil {
					b.Fatal("accepted a bad token")
				}
			}
		})
	}
}
