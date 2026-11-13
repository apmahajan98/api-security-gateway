# IEEE-Style Report

This directory contains the IEEE conference-style report for the API security
gateway project. Replace the author block, placeholder prose, page ranges, and
illustrative measurements before submission.

## IEEE Submission Checklist

Before submitting, confirm that the report includes:

- A centered title, followed by every author's name, affiliation, and email
  address.
- Two-column IEEE formatting using Times New Roman, 10-point text.
- An `Abstract` at the beginning of the paper.
- `Keywords` or IEEE `Index Terms` directly below the abstract. Do not omit
  them; the `IEEEkeywords` environment supplies this section.
- A clear `Introduction`, logically organized numbered sections, and properly
  nested headings such as `\section`, `\subsection`, and `\subsubsection`.
- Figures and tables placed at the top or bottom of a column, not in the middle
  of a column.
- A descriptive caption/remark for every figure and table explaining what it
  shows. In IEEE style, place figure captions below figures and table captions
  above tables.
- Page numbers on the report.
- A `References` section with every source cited in the paper. Include the
  required source types, such as papers, books, technical reports, and web
  sources. Direct quotations must include a page-specific citation, for example
  `\cite[p.~12]{source}`.
- A `pages` field for each bibliography entry where page information applies.
  Use the actual page or page range; do not leave it blank because missing
  reference page numbers may lose marks.

The current `.tex` file contains examples of the abstract, index terms,
sections, headings, figure caption, table caption, equations, citations, and
bibliography.

## Setup

The report does not require the Python virtual environment.

Install Tectonic using one of these options:

### macOS with Homebrew

```bash
brew install tectonic
```

### Windows, macOS, or Linux with Conda

```bash
conda install -c conda-forge tectonic
```

Verify the installation:

```bash
tectonic --version
```

## Generate the PDF

From the repository root:

```bash
cd report
tectonic report.tex
```

The generated file will be `report/report.pdf`. Tectonic automatically
downloads required LaTeX packages and handles the compilation passes needed
for citations, figures, equations, and references.

Run each command on its own line. Do not add a trailing backslash (`\\`) to
commands.

## Collaboration

- Edit the main report in `report.tex`.
- Edit bibliography entries in `references.bib`.
- Replace placeholder authors, lorem ipsum text, page ranges, and example
  measurements before submission.
- Replace placeholder bibliography page ranges with the actual pages used.
- Cite every paper, book, report, web source, and direct quotation that appears
  in the report.
- Run `tectonic report.tex` before opening a pull request.
- Do not commit generated PDF files unless the group agrees.

For detailed installation options, see the official Tectonic guide:
https://tectonic-typesetting.github.io/en-US/install.html
