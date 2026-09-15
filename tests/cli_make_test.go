package tests

import (
	"strings"
	"testing"

	"struct-framework/internal/app/codegen"
)

func TestCodegen_MVCComponents(t *testing.T) {
	module := "struct-framework"
	name := "Invoice"

	// 1. Model
	path, src := codegen.Model(module, name)
	if !strings.HasSuffix(path, "internal/mvc/models/invoice.go") || !strings.Contains(src, "type Invoice struct") {
		t.Fatalf("unexpected Model codegen: %s\n%s", path, src)
	}

	// 2. Controller
	path, src = codegen.Controller(module, name)
	if !strings.HasSuffix(path, "internal/mvc/controllers/invoice_controller.go") || !strings.Contains(src, "type InvoiceController struct") {
		t.Fatalf("unexpected Controller codegen: %s\n%s", path, src)
	}

	// 3. Service
	path, src = codegen.Service(module, name)
	if !strings.HasSuffix(path, "internal/mvc/services/invoice_service.go") || !strings.Contains(src, "type InvoiceService interface") {
		t.Fatalf("unexpected Service codegen: %s\n%s", path, src)
	}

	// 4. DTO
	path, src = codegen.DTO(module, name)
	if !strings.HasSuffix(path, "internal/mvc/views/invoice_view.go") || !strings.Contains(src, "type InvoiceResponse struct") {
		t.Fatalf("unexpected DTO codegen: %s\n%s", path, src)
	}

	// 5. Enum
	path, src = codegen.Enum(module, "InvoiceStatus", []string{"draft", "issued", "paid"})
	if !strings.HasSuffix(path, "internal/mvc/models/invoice_status_enum.go") || !strings.Contains(src, "InvoiceStatusDraft") {
		t.Fatalf("unexpected Enum codegen: %s\n%s", path, src)
	}

	// 6. Policy
	implPath, implSrc, testPath, testSrc := codegen.Policy(module, name)
	if !strings.HasSuffix(implPath, "internal/platform/security/authz/invoice_policy.go") || !strings.Contains(implSrc, "type InvoicePolicy struct") {
		t.Fatalf("unexpected Policy impl codegen: %s\n%s", implPath, implSrc)
	}
	if !strings.HasSuffix(testPath, "internal/platform/security/authz/invoice_policy_test.go") || !strings.Contains(testSrc, "TestInvoicePolicy_DeniesByDefault") {
		t.Fatalf("unexpected Policy test codegen: %s\n%s", testPath, testSrc)
	}

	// 7. Event
	path, src = codegen.Event(module, "InvoicePaid")
	if !strings.HasSuffix(path, "internal/platform/events/invoice_paid_event.go") || !strings.Contains(src, "type InvoicePaidV1 struct") {
		t.Fatalf("unexpected Event codegen: %s\n%s", path, src)
	}

	// 8. Job
	path, src = codegen.Job(module, "ProcessInvoice")
	if !strings.HasSuffix(path, "internal/support/queue/process_invoice_job.go") || !strings.Contains(src, "type ProcessInvoiceJob struct") {
		t.Fatalf("unexpected Job codegen: %s\n%s", path, src)
	}

	// 9. Repositories (Postgres & MySQL)
	pgPath, pgSrc := codegen.RepositoryPostgres(module, name)
	if !strings.HasSuffix(pgPath, "internal/platform/store/postgres/invoice_repository.go") || !strings.Contains(pgSrc, "type InvoiceRepository struct") {
		t.Fatalf("unexpected Postgres Repository codegen: %s\n%s", pgPath, pgSrc)
	}
	myPath, mySrc := codegen.RepositoryMySQL(module, name)
	if !strings.HasSuffix(myPath, "internal/platform/store/mysql/invoice_repository.go") || !strings.Contains(mySrc, "type InvoiceRepository struct") {
		t.Fatalf("unexpected MySQL Repository codegen: %s\n%s", myPath, mySrc)
	}
}
