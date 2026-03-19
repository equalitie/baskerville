package payment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	stripe "github.com/stripe/stripe-go/v84"
)

/*
NOTE: this is a TEST version, its a single server setup, everything is stored in memory no persistence its just for testing
its well known that stripe search is not strongly consistent
stripe’s customer search is documented as not ideal for read-after-write flows and can lag
for now its fine here because we only re-check every 28 days, but if a customer pays and immediately expects access,
using a direct customer ID or subscription ID mapped to the API key would be stronger
*/

const (
	checkTTL = 28 * 24 * time.Hour
)

// the PaymentChecker type basically just owns the in memory cache and stripe client
type PaymentChecker struct {
	stripe *stripe.Client

	mu      sync.Mutex
	entries map[string]*paymentEntry
}

type paymentEntry struct {
	paid      bool
	checkedAt time.Time

	checking bool //to dedupe concurrent Stripe lookups for the same cache key
	waitCh   chan struct{}
}

func NewPaymentChecker(stripeSecretKey string) *PaymentChecker {
	return &PaymentChecker{
		stripe:  stripe.NewClient(stripeSecretKey),
		entries: make(map[string]*paymentEntry),
	}
}

/*
ValidatePaidAccess returns nil when access should be allowed.
it caches the result for 28 days per (domain, apiKey).
*/
func (p *PaymentChecker) ValidatePaidAccess(ctx context.Context, apiKey, siteURL string) error {
	domain, err := normalizeDomain(siteURL)
	if err != nil {
		return fmt.Errorf("invalid site url: %w", err)
	}

	cacheKey := makeCacheKey(domain, apiKey)

	for {
		p.mu.Lock()
		entry, ok := p.entries[cacheKey]
		now := time.Now()

		//if its a fresh cached result we can use it.
		if ok && now.Sub(entry.checkedAt) < checkTTL {
			paid := entry.paid
			p.mu.Unlock()

			if !paid {
				return errors.New("subscription inactive")
			}
			return nil
		}

		//someone else is already refreshing this entry so just wait for them
		if ok && entry.checking {
			waitCh := entry.waitCh
			p.mu.Unlock()

			select {
			case <-waitCh:
				//koop and re read the refreshed entry
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		//we will perform the Stripe check
		if !ok {
			entry = &paymentEntry{}
			p.entries[cacheKey] = entry
		}
		entry.checking = true
		entry.waitCh = make(chan struct{})
		p.mu.Unlock()

		paid, checkErr := p.checkStripePaid(ctx, apiKey, domain)

		p.mu.Lock()
		entry.paid = paid
		entry.checkedAt = time.Now()
		entry.checking = false
		close(entry.waitCh)
		entry.waitCh = nil
		p.mu.Unlock()

		if checkErr != nil {
			/*
				TODO: we still need to think through failure modes and stuff
				like fail-closed is stricter/safer for paid access control
			*/
			return fmt.Errorf("payment check failed: %w", checkErr)
		}

		if !paid {
			return errors.New("subscription inactive")
		}
		return nil
	}
}

func makeCacheKey(domain, apiKey string) string {
	return domain + "|" + apiKey
}

func normalizeDomain(siteURL string) (string, error) {
	siteURL = strings.TrimSpace(siteURL)
	if siteURL == "" {
		return "", errors.New("empty site url")
	}

	if !strings.Contains(siteURL, "://") {
		siteURL = "https://" + siteURL
	}

	u, err := url.Parse(siteURL)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	if host == "" {
		return "", errors.New("missing hostname")
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")

	if ip := net.ParseIP(host); ip != nil {
		return "", errors.New("site url must contain a domain, not an IP")
	}

	return host, nil
}

func (p *PaymentChecker) StartJanitor(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (p *PaymentChecker) cleanup() {
	cutoff := time.Now().Add(-2 * checkTTL)

	p.mu.Lock()
	defer p.mu.Unlock()

	for k, v := range p.entries {
		if !v.checking && v.checkedAt.Before(cutoff) {
			delete(p.entries, k)
		}
	}
}
