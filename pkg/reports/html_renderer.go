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

func renderReadinessHTML(outputPath string, data *ReportData) error {
	tmpl, err := template.New("base.html").Funcs(templateFuncs()).ParseFS(templateFS, "templates/base.html", "templates/readiness.html")
	if err != nil {
		return fmt.Errorf("parse readiness templates: %w", err)
	}
	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return tmpl.Execute(w, data)
	})
}

func renderExecutiveHTML(outputPath string, data *ReportData) error {
	tmpl, err := template.New("base.html").Funcs(templateFuncs()).ParseFS(templateFS, "templates/base.html", "templates/executive.html")
	if err != nil {
		return fmt.Errorf("parse executive templates: %w", err)
	}
	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return tmpl.Execute(w, data)
	})
}

func renderControlDetailHTML(outputPath string, detail *ControlDetail, version string) error {
	tmpl, err := template.New("control_detail.html").Funcs(templateFuncs()).ParseFS(templateFS, "templates/control_detail.html")
	if err != nil {
		return fmt.Errorf("parse control detail template: %w", err)
	}

	templateData := struct {
		*ControlDetail
		Version string
	}{
		ControlDetail: detail,
		Version:       version,
	}

	return writeToFileOrStdout(outputPath, func(w io.Writer) error {
		return tmpl.Execute(w, templateData)
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
	defer f.Close()

	if err := fn(f); err != nil {
		return err
	}
	return f.Close()
}
