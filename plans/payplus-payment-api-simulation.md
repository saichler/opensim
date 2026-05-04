# Plan: PayPlus Payment Gateway API Simulation

## Overview

Add simulation of PayPlus's REST API (`restapi.payplus.co.il/api/v1.0/`) to l8opensim. PayPlus is an Israeli payment processing platform offering credit card charging, tokenization, recurring payments, refunds, invoicing, and device-based (POS terminal) transactions. Each simulated "device" represents a PayPlus merchant account serving payment API requests.

Unlike the Nayax Cloud simulator (which models a fleet of vending machines with inventory), the PayPlus simulator models a **payment gateway** — it accepts charge requests, returns approval codes, manages tokens and customers, and produces transaction history.

**Base URLs (real):**
- Production: `https://restapi.payplus.co.il/api/v1.0/`
- Staging: `https://restapidev.payplus.co.il/api/v1.0/`

**Authentication:** All endpoints require `api-key` and `secret-key` headers. The simulator will accept any non-empty values (permissive mode, same approach as Nayax auth).

## Scope

### What gets simulated

| API Area | Endpoints | Purpose |
|---|---|---|
| **Transactions** | Charge (J4), Check (J2), ChargeByUID, RefundByUID, View | Core payment processing |
| **Payment Pages** | GenerateLink, List, ChargeMethods, IPN | Hosted payment page flow |
| **Tokens** | Add, List, Update | Card tokenization for recurring use |
| **Customers** | Add | Customer record management |
| **Products** | Add, Update, View | Product catalog for invoicing |
| **Categories** | Add, Update, View | Product categorization |
| **Recurring Payments** | Add, View, AddCharge, UpdateCharge, DeleteCharge, ChargedReport | Subscription billing |
| **Documents (Invoice+)** | DocTypes, DocsList | Invoice and receipt queries |
| **Cashiers** | Add, Remove, ResetRemove | Cashier management |
| **Transaction Reports** | TransactionsHistory | Reporting and reconciliation |
| **Devices** | TransactionByDevice | POS terminal integration |

### What does NOT get simulated

- Hosted Fields iframe rendering (browser-side JS plugin — not an API)
- 3D Secure challenge flow (interactive browser redirect)
- Webhook/IPN outbound callbacks (requires the simulator to POST to external URLs)
- Apple Pay / Google Pay wallet tokenization flows
- Actual card network validation (BIN checks, Luhn, etc.)
- PayPlus admin console UI

### Device flavors

Three resource profiles representing different merchant scales:

| Resource file | Profile | Terminals | Customers | Monthly transactions |
|---|---|---|---|---|
| `payplus_small` | Small merchant | 1 terminal, 1 cashier | ~50 | ~500 |
| `payplus_medium` | Mid-size business | 3 terminals, 5 cashiers | ~500 | ~5,000 |
| `payplus_large` | Enterprise/chain | 10 terminals, 20 cashiers | ~5,000 | ~50,000 |

---

## Phase 0: Resource File Structure

Resources follow the existing l8opensim directory convention. Each size profile is a directory with files split by API area to stay under the 500-line maintainability cap:

```
go/simulator/resources/payplus_small/
├── payplus_transactions.json      # Phase 1: Charge, Check, Refund, View
├── payplus_payment_pages.json     # Phase 2: GenerateLink, List, ChargeMethods
├── payplus_tokens_customers.json  # Phase 3: Token CRUD, Customer Add
├── payplus_products.json          # Phase 4: Products, Categories
├── payplus_recurring.json         # Phase 5: Recurring payments
├── payplus_reports_docs.json      # Phase 6: Reports, Documents, Cashiers, Devices

go/simulator/resources/payplus_medium/
└── (same six files, larger datasets)

go/simulator/resources/payplus_large/
└── (same six files, largest datasets)
```

Each file follows the `DeviceResources` schema:
```json
{
  "snmp": [],
  "ssh": [],
  "api": [ /* endpoints for this area */ ]
}
```

All API paths are prefixed with `/api/v1.0/` to match the real PayPlus URL structure.

---

## Phase 1: Transaction Endpoints (core payment flow)

File: `payplus_<size>/payplus_transactions.json`

### 1.1 Charge Transaction (J4)

```
POST /api/v1.0/Transactions/Charge
```

**Request body fields:**
- `terminal_uid` (string, required)
- `cashier_uid` (string, required)
- `amount` (number, required)
- `currency_code` (string, default "ILS")
- `credit_terms` (integer: 1=regular, 6=credit, 8=payment)
- `use_token` (boolean)
- `token` (string, required if use_token=true)
- `customer_uid` (string)
- `credit_card` (object: `card_number`, `card_date_mmyy`, `card_holder_id`, `card_holder_name`, `cvv`)
- `create_token` (boolean)
- `initial_invoice` (boolean)
- `payments` (object: installment configuration)
- `more_info` through `more_info_5` (strings)

**Response (200):**
```json
{
  "results": { "status": "success", "code": 0, "description": "operation has been success" },
  "data": {
    "transaction_uid": "TXN-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "number": 100234,
    "type": "Charge",
    "amount": 15000,
    "currency_code": "ILS",
    "credit_terms": 1,
    "date": "2026-04-17T09:14:22Z",
    "status_code": "000",
    "approval_num": "0012345",
    "voucher_num": "V-789012",
    "card_brand": "visa",
    "card_type": "credit",
    "four_digits": "4580",
    "expiry_month": "12",
    "expiry_year": "2028",
    "token_uid": null,
    "customer_uid": null,
    "more_info": null
  }
}
```

### 1.2 Check Card (J2)

```
POST /api/v1.0/Transactions/Check
```

Same request structure as Charge. Response confirms card validity without holding funds:
```json
{
  "results": { "status": "success", "code": 0, "description": "card is valid" },
  "data": {
    "transaction_uid": "TXN-...",
    "type": "Check",
    "status_code": "000",
    "card_brand": "visa",
    "four_digits": "4580"
  }
}
```

### 1.3 Charge by Transaction UID (J5 completion)

```
POST /api/v1.0/Transactions/ChargeByTransactionUID
```

**Request:** `transaction_uid`, `amount` (up to original approval amount)
**Response:** Same structure as Charge with `type: "ChargeByUID"`

### 1.4 Refund by Transaction UID

```
POST /api/v1.0/Transactions/RefundByTransactionUID
```

**Request:** `transaction_uid`, `amount`, optional `more_info`, `cvv`, `initial_invoice`, `items`
**Response:**
```json
{
  "results": { "status": "success", "code": 0, "description": "refund has been success" },
  "data": {
    "transaction_uid": "TXN-...",
    "type": "Refund",
    "amount": 5000,
    "original_transaction_uid": "TXN-..."
  }
}
```

### 1.5 View Transaction

```
POST /api/v1.0/Transactions/View
```

**Request:** `transaction_uid` or `customer_uid`, optional `fromDate`/`untilDate`, `more_info`
**Response:** Array of transaction records with full details.

### 1.6 Flavorable transaction data

- **Transaction UIDs**: `TXN-{UUIDv4}`
- **Approval numbers**: 7-digit numeric strings
- **Voucher numbers**: `V-{6-digit}`
- **Card brands**: visa, mastercard, amex, isracard, diners (weighted: 40% visa, 30% mastercard, 15% isracard, 10% amex, 5% diners)
- **Amounts**: Realistic for Israeli market — 500-50000 agorot (5-500 ILS)
- **Currency codes**: ILS (80%), USD (15%), EUR (5%)
- **Status codes**: "000" (approved), "001" (declined — 5% of transactions), "002" (insufficient funds — 3%)
- **Credit terms**: 1 (regular, 70%), 8 (payments/installments, 25%), 6 (credit, 5%)

---

## Phase 2: Payment Pages

File: `payplus_<size>/payplus_payment_pages.json`

### 2.1 Generate Payment Link

```
POST /api/v1.0/PaymentPages/generateLink
```

**Key request fields:** `payment_page_uid`, `amount`, `currency_code`, `charge_method` (0-5), `refURL_success`, `refURL_failure`, `refURL_callback`, `payments`, `create_token`, `customer`, `items`, `language_code`, `expiry_datetime`

**Response:**
```json
{
  "results": { "status": "success", "code": 0, "description": "operation has been success" },
  "data": {
    "page_request_uid": "PRQ-xxxxxxxx",
    "payment_page_link": "https://payments.payplus.co.il/page/PRQ-xxxxxxxx"
  }
}
```

### 2.2 Payment Pages List

```
GET /api/v1.0/PaymentPages/list
```

Returns list of configured payment pages with UIDs, names, and settings.

### 2.3 Available Charge Methods

```
GET /api/v1.0/PaymentPages/chargeMethods
```

Returns available charge methods (credit-card, bit, multipass, paypal, google-pay, apple-pay).

### 2.4 IPN (Instant Payment Notification)

```
POST /api/v1.0/PaymentPages/ipn
```

Returns the transaction result for a given `page_request_uid`.

---

## Phase 3: Tokens and Customers

File: `payplus_<size>/payplus_tokens_customers.json`

### 3.1 Token Add

```
POST /api/v1.0/Token/Add
```

**Request:** `terminal_uid`, `customer_uid`, `credit_card_number`, `card_date_mmyy`, `identification_number`
**Response:** Token UID, masked card number, expiry

### 3.2 Token List

```
POST /api/v1.0/Token/List
```

**Request:** `terminal_uid`, optional `customer_uid`, `skip`, `take`, `filter`
**Response:** Array of tokens with `token`, `last_4_digits`, `card_date_mmyy`, `customer_uid`, `name`

### 3.3 Token Update

```
POST /api/v1.0/Token/Update/{uid}
```

### 3.4 Customer Add

```
POST /api/v1.0/Customers/Add
```

**Request:** `email`, `customer_name`, optional `paying_vat`, `vat_number`, `phone`, `contacts`, `business_address`, `business_city`, `business_country_iso`
**Response:**
```json
{
  "results": { "status": "success", "code": 0, "description": "operation has been success" },
  "data": { "customer_uid": "CUS-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }
}
```

### 3.5 Flavorable data

- **Token UIDs**: `TOK-{UUIDv4}`
- **Customer UIDs**: `CUS-{UUIDv4}`
- **Customer names**: Israeli first+last name arrays (e.g., "David Cohen", "Noa Levy", "Yossi Mizrahi")
- **Card numbers (masked)**: `**** **** **** 4580`, last-4 from curated array
- **Emails**: `{firstname}.{lastname}@{domain}` with domains: gmail.com, walla.co.il, yahoo.com, outlook.co.il

---

## Phase 4: Products and Categories

File: `payplus_<size>/payplus_products.json`

### 4.1 Products

```
POST /api/v1.0/Products/Add
POST /api/v1.0/Products/Update/{uid}
GET  /api/v1.0/Products/View
```

**Product fields:** `name`, `price` (agorot), `currency_code`, `vat_type` (0=included, 1=not included, 2=exempt), `barcode`, `description`, `category_uids`, `valid`

### 4.2 Categories

```
POST /api/v1.0/Categories/Add
POST /api/v1.0/Categories/Update/{uid}
GET  /api/v1.0/Categories/View
```

### 4.3 Flavorable data

- **Product UIDs**: `PRD-{UUIDv4}`
- **Product names**: Israeli retail items (e.g., "קפה שחור", "סלט קיסר", "פיצה מרגריטה", "מים מינרליים")
- **Prices**: 500-15000 agorot (5-150 ILS)
- **Categories**: "Drinks", "Food", "Services", "Subscriptions"

---

## Phase 5: Recurring Payments

File: `payplus_<size>/payplus_recurring.json`

### 5.1 Endpoints

```
POST /api/v1.0/RecurringPayments/Add
GET  /api/v1.0/RecurringPayments/{uid}/ViewRecurring
GET  /api/v1.0/RecurringPayments/{uid}/ViewRecurringCharge
POST /api/v1.0/RecurringPayments/AddRecurringCharge/{uid}
POST /api/v1.0/RecurringPayments/UpdateRecurringCharge/{charge_uid}
POST /api/v1.0/RecurringPayments/DeleteRecurringCharge/{charge_uid}
POST /api/v1.0/RecurringPayments/GetRecurringCharge
GET  /api/v1.0/RecurringPaymentsReports/Charged
POST /api/v1.0/RecurringPayments/CreditCardRenewal/{recurring_uid}
```

### 5.2 Flavorable data

- **Recurring UIDs**: `REC-{UUIDv4}`
- **Charge UIDs**: `CHG-{UUIDv4}`
- **Frequencies**: monthly (70%), weekly (15%), yearly (15%)
- **Amounts**: Subscription-realistic — 2900-29900 agorot (29-299 ILS/month)
- **Statuses**: active (80%), paused (10%), cancelled (10%)

---

## Phase 6: Reports, Documents, Cashiers, Devices

File: `payplus_<size>/payplus_reports_docs.json`

### 6.1 Transaction Reports

```
POST /api/v1.0/TransactionReports/TransactionsHistory
```

**Request:** `terminal_uid`, `filter` object, `skip`, `take` (max 500)
**Response:** Paginated array of transaction records with `recurring_number`, `customer_name`, `customer_uid`, `currency_code`, `execution_date`, `charge_type`, `card_number`, `amount`, `uid`

### 6.2 Documents (Invoice+)

```
GET /api/v1.0/books/doc-types
GET /api/v1.0/books/docs/list
```

**Doc list filters:** `search`, `number`, `transaction_uuid`, `currency_code`, `customer`, `fromDate`, `toDate`, `types` (tax_invoice, receipt, proforma, refund_invoice, quote), `statuses` (OPEN, CLOSED, CANCELLED), `minAmount`, `maxAmount`

### 6.3 Cashiers

```
POST /api/v1.0/Cashiers/Add
POST /api/v1.0/Cashiers/Remove
POST /api/v1.0/Cashiers/ResetRemove
```

### 6.4 Device Transactions

```
POST /api/v1.0/Devices/TransactionByDevice
```

**Request:** `device_uid`, `charge_method`, `amount`, `currency_code`, `refURL_callback`
**Response:** Same structure as Charge transaction with device context.

### 6.5 Flavorable data

- **Document numbers**: `DOC-{sequential}`
- **Document types**: tax_invoice (50%), receipt (30%), proforma (10%), refund_invoice (5%), quote (5%)
- **Cashier names**: Israeli names from the same curated array as customers
- **Terminal UIDs**: `TRM-{UUIDv4}`
- **Cashier UIDs**: `CSH-{UUIDv4}`
- **Device UIDs**: `DEV-{UUIDv4}`

---

## Phase 7: Device Profile and Round-Robin Registration

### 7.1 device_profiles.go

Add a lightweight profile for PayPlus (cloud API, not hardware):

```go
var profilePayPlus = DeviceProfile{
    CPUBaseMin: 5, CPUBaseMax: 20, CPUSpike: 5,
    MemTotalKB: 2 * 1024 * 1024, // 2 GB
    MemBaseMin: 20, MemBaseMax: 50, MemVariance: 5,
    TempBaseMin: 22, TempBaseMax: 30, TempSpike: 2,
}
```

Map all three sizes:
```go
"payplus_small":  profilePayPlus,
"payplus_medium": profilePayPlus,
"payplus_large":  profilePayPlus,
```

### 7.2 types.go

Append to `RoundRobinDeviceTypes`:
```go
"payplus_small",
"payplus_medium",
"payplus_large",
```

### 7.3 personalizeResponse enhancement

The existing `personalizeResponse` in `api.go` handles machineId replacement and slot variation for Nayax. PayPlus responses use different ID patterns. Add support for:

- Replace `terminal_uid` fields when a `terminal_uid` path parameter is present
- Replace `transaction_uid` fields with deterministic per-device UUIDs
- Vary `amount` fields using the existing `varyNumber` function
- Vary `status_code` (most "000", some "001"/"002" based on hash)

This extends the existing personalization without breaking Nayax behavior — the logic already checks for field existence before replacing.

---

## Phase 8: End-to-End Verification

For every size profile (small, medium, large):

1. **Startup**
   - Boot simulator with payplus resource files
   - Confirm HTTPS listener starts

2. **Transaction smoke tests**
   - `POST /api/v1.0/Transactions/Charge` with card data → 200, status "success"
   - `POST /api/v1.0/Transactions/Check` → 200
   - `POST /api/v1.0/Transactions/RefundByTransactionUID` → 200
   - `POST /api/v1.0/Transactions/View` → 200 with transaction array

3. **Payment Pages smoke tests**
   - `POST /api/v1.0/PaymentPages/generateLink` → 200 with payment link
   - `GET /api/v1.0/PaymentPages/chargeMethods` → 200

4. **Token and Customer smoke tests**
   - `POST /api/v1.0/Token/Add` → 200 with token UID
   - `POST /api/v1.0/Token/List` → 200 with token array
   - `POST /api/v1.0/Customers/Add` → 200 with customer UID

5. **Recurring payment smoke tests**
   - `POST /api/v1.0/RecurringPayments/Add` → 200
   - `GET /api/v1.0/RecurringPayments/{uid}/ViewRecurringCharge` → 200

6. **Reports and Documents smoke tests**
   - `POST /api/v1.0/TransactionReports/TransactionsHistory` → 200
   - `GET /api/v1.0/books/docs/list` → 200
   - `GET /api/v1.0/books/doc-types` → 200

7. **Per-device variance**
   - Two instances of `payplus_medium` on different IPs
   - `POST /api/v1.0/Transactions/Charge` on both → different transaction UIDs, amounts varied

8. **Negative tests**
   - Unknown path → 405
   - Missing required headers → still 200 (permissive auth, known deviation)

9. **Go test** at `go/tests/TestPayPlus_test.go`
   - Boot two `DeviceSimulator` instances with `payplus_medium` resources
   - Assert 200 on Charge, Token/List, TransactionsHistory
   - Assert two devices return different transaction UIDs

---

## Traceability Matrix

| # | Area | Action Item | Phase |
|---|---|---|---|
| 1 | Directory structure | Create `resources/payplus_{small,medium,large}/` with 6 JSON files each | Phase 0 |
| 2 | Transactions | Author Charge, Check, ChargeByUID, RefundByUID, View endpoints | Phase 1 |
| 3 | Payment Pages | Author GenerateLink, List, ChargeMethods, IPN endpoints | Phase 2 |
| 4 | Tokens + Customers | Author Token Add/List/Update, Customer Add | Phase 3 |
| 5 | Products | Author Product Add/Update/View, Category Add/Update/View | Phase 4 |
| 6 | Recurring | Author 9 recurring payment endpoints | Phase 5 |
| 7 | Reports + Docs + Cashiers + Devices | Author TransactionsHistory, DocTypes, DocsList, Cashier CRUD, TransactionByDevice | Phase 6 |
| 8 | Device profile | Add `profilePayPlus`, map three sizes | Phase 7.1 |
| 9 | Round-robin | Add three directory names to `RoundRobinDeviceTypes` | Phase 7.2 |
| 10 | Response personalization | Extend `personalizeResponse` for PayPlus ID patterns | Phase 7.3 |
| 11 | Smoke tests | Per-profile endpoint coverage | Phase 8.1-8.6 |
| 12 | Variance verification | Two-device diff test | Phase 8.7 |
| 13 | Go test | `go/tests/TestPayPlus_test.go` | Phase 8.9 |

---

## PayPlus API Reference Summary

**Base URL:** `https://restapi.payplus.co.il/api/v1.0/`

**Auth headers (all endpoints):** `api-key`, `secret-key`

**Standard response envelope:**
```json
{
  "results": { "status": "success|error", "code": 0, "description": "..." },
  "data": { /* endpoint-specific */ }
}
```

**Charge methods:**
| Value | Type | Description |
|-------|------|-------------|
| 0 | Card Check (J2) | Validate card without holding funds |
| 1 | Charge (J4) | Immediate payment |
| 2 | Approval (J5) | Reserve funds without charging |
| 3 | Recurring | Automatic subscription billing |
| 4 | Refund | Immediate refund |
| 5 | Token | Tokenize card for future use |

**Supported currencies:** ILS, USD, EUR, GBP

**Credit terms:**
| Value | Type |
|-------|------|
| 1 | Regular (single charge) |
| 6 | Credit (deferred) |
| 8 | Payments (installments) |

---

## Risks and Open Questions

1. **No outbound webhooks.** Real PayPlus sends callbacks to `refURL_callback` after transactions. The simulator returns results synchronously but does not POST to external URLs. This is a known deviation — add as a follow-up if needed.
2. **Auth is permissive.** Real PayPlus rejects requests without valid `api-key`/`secret-key`. The simulator accepts any non-empty values. Same approach as Nayax.
3. **No real card validation.** The simulator does not validate card numbers (Luhn), expiry dates, or CVV. Any card data returns a success response. Decline responses are based on hash-based variation, not card data.
4. **Pagination.** PayPlus uses `skip`/`take` parameters (max 500). The simulator returns the full canned dataset regardless of skip/take values. Can be enhanced later.
5. **Israeli market specifics.** PayPlus is Israel-focused: ILS currency, Israeli ID numbers (`teudat_zehut`), VAT handling (17% MA'AM), Hebrew product names. The simulator data reflects this.
6. **Invoice+ module.** Document generation (`initial_invoice: true`) is an add-on feature. The simulator returns pre-authored document responses regardless of the flag.

---

## Sources

- [PayPlus API Introduction](https://docs.payplus.co.il/reference/introduction)
- [PayPlus REST API URLs](https://docs.payplus.co.il/reference/payplus-rest-api-urls)
- [Generate Payment Link](https://docs.payplus.co.il/reference/post_paymentpages-generatelink)
- [Charge Transaction (J4)](https://docs.payplus.co.il/reference/post_transactions-charge)
- [Check Card (J2)](https://docs.payplus.co.il/reference/post_transactions-check)
- [Refund by Transaction UID](https://docs.payplus.co.il/reference/post_transactions-refundbytransactionuid)
- [Token Add](https://docs.payplus.co.il/reference/post_token-add)
- [Token List](https://docs.payplus.co.il/reference/post_token-list)
- [Customer Add](https://docs.payplus.co.il/reference/create-a-resource)
- [Products Add](https://docs.payplus.co.il/reference/post_products-add)
- [Recurring Charges List](https://docs.payplus.co.il/reference/get_recurringpayments-uid-viewrecurringcharge)
- [Transactions History](https://docs.payplus.co.il/reference/post_transactionreports-transactionshistory)
- [Documents List](https://docs.payplus.co.il/reference/get_books-docs-list)
- [Devices](https://docs.payplus.co.il/reference/devices-1)
- [Hosted Fields](https://docs.payplus.co.il/reference/hosted-fields)
- [Cashiers Add](https://docs.payplus.co.il/reference/post_cashiers-add)
- [Transaction View](https://docs.payplus.co.il/reference/post_transactions-view)
- [Website or App Integration](https://docs.payplus.co.il/reference/website-or-app)
- [Payment Methods](https://docs.payplus.co.il/reference/payment-methods)
- [Charge by Transaction UID](https://docs.payplus.co.il/reference/post_transactions-chargebytransactionuid)
