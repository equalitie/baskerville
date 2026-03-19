package payment

import (
	"context"
	"fmt"
	"strings"

	stripe "github.com/stripe/stripe-go/v84"
)

/*
NOTE: this is a TEST version, its a single server setup, everything is stored in memory no persistence its just for testing
its well known that stripe search is not strongly consistent
stripe’s customer search is documented as not ideal for read-after-write flows and can lag
for now its fine here because we only re-check every 28 days, but if a customer pays and immediately expects access,
using a direct customer ID or subscription ID mapped to the API key would be stronger
*/

/*
accoding to the docs the best practice here is to search using metadata we control
but this pressupposes we set these metadata keys when creating the customer
so this is definitely still TODO cause I need to discuss with Anton what to include
*/
func (p *PaymentChecker) checkStripePaid(ctx context.Context, apiKey, domain string) (bool, error) {
	query := fmt.Sprintf(
		`metadata["wpsec_api_key"]:"%s" AND metadata["wpsec_domain"]:"%s"`,
		escapeStripeSearchValue(apiKey),
		escapeStripeSearchValue(domain),
	)

	searchParams := &stripe.CustomerSearchParams{
		SearchParams: stripe.SearchParams{
			Query: query,
		},
	}

	var customerID string
	for c, err := range p.stripe.V1Customers.Search(ctx, searchParams) {
		if err != nil {
			return false, err
		}
		if c != nil {
			customerID = c.ID
			break
		}
	}

	if customerID == "" {
		return false, nil
	}

	subParams := &stripe.SubscriptionListParams{
		Customer: stripe.String(customerID),
		Status:   stripe.String("all"),
	}

	for sub, err := range p.stripe.V1Subscriptions.List(ctx, subParams) {
		if err != nil {
			return false, err
		}
		if sub == nil {
			continue
		}

		switch sub.Status {
		case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusTrialing:
			return true, nil
		}
	}

	return false, nil
}

/*
NOTE:
stripe search uses single-quoted string literals in their examples
also escaping single quotes/backslashes defensively is enough here
*/
func escapeStripeSearchValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}
