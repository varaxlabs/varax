package reports

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	readinessTmpl    *template.Template
	executiveTmpl    *template.Template
	controlDetailTmpl *template.Template
)

func init() {
	funcs := templateFuncs()
	readinessTmpl = template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(templateFS, "templates/base.html", "templates/readiness.html"),
	)
	executiveTmpl = template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(templateFS, "templates/base.html", "templates/executive.html"),
	)
	controlDetailTmpl = template.Must(
		template.New("control_detail.html").Funcs(funcs).ParseFS(templateFS, "templates/control_detail.html"),
	)
}

func renderReadinessHTML(outputPath string, data *ReportData) error {
	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return readinessTmpl.Execute(w, data)
	})
}

func renderExecutiveHTML(outputPath string, data *ReportData) error {
	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return executiveTmpl.Execute(w, data)
	})
}

func renderControlDetailHTML(outputPath string, detail *ControlDetail, version string) error {
	templateData := struct {
		*ControlDetail
		Version string
	}{
		ControlDetail: detail,
		Version:       version,
	}

	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return controlDetailTmpl.Execute(w, templateData)
	})
}

func writeToFileOrStdout(path string, fn func(w io.Writer) error) error {
	if path == "" || path == "-" {
		return fn(os.Stdout)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := fn(f); err != nil {
		return err
	}
	return f.Close()
}
