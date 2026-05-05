# Talk

A Beamer talk on the AI-assisted reverse-engineering work in this
repository, intended for a CCC Congress audience.

## Sources

- `slides.tex` — the slide deck plus speaker notes, in one file.
- `title-graphic.tex` — the three-stage boot trampoline diagram used on
  the title slide. Built once into `title-graphic.pdf` and embedded.
- `Makefile` — three build targets (slides / notes / handout).

## Building

Requires a TeX Live distribution with Beamer and the metropolis theme.
On Debian/Ubuntu:

```sh
apt install texlive-latex-base texlive-latex-extra texlive-fonts-extra \
            texlive-pictures texlive-publishers texlive-bibtex-extra
```

Or, more simply if you have the disk:

```sh
apt install texlive-full
```

Then:

```sh
make            # slides.pdf — what the audience sees on screen
make notes      # slides-notes.pdf — slide on the left, speaker notes on
                #   the right, formatted for the Beamer two-screen presenter
                #   mode (use with `pdfpc` or your favourite presenter tool)
make handout    # slides-handout.pdf — every overlay collapsed onto a
                #   single page, no notes, suitable for printing
make all        # all three of the above
make clean      # remove intermediate build artefacts
make distclean  # also remove the final PDFs and title-graphic.pdf
```

The `build/` directory holds intermediate `.aux` / `.log` / `.toc`
files; the final PDFs are copied up to the source directory.

## Driving the talk

For live presentation I'd recommend [`pdfpc`](https://pdfpc.github.io/):

```sh
make notes
pdfpc slides-notes.pdf
```

`pdfpc` reads the two-pane PDF and shows the slide on one display, the
notes on the laptop. If you prefer a single-pane workflow, build
`slides.pdf` and use any standard PDF viewer in fullscreen.

## Editing

The talk is one file (`slides.tex`). Sections are marked with
`\section{...}` and frames with `\begin{frame}...\end{frame}`. Speaker
notes are inside `\note{...}` blocks at the end of each frame's body.

A few sharp edges to remember when editing:

- Frames containing `lstlisting` blocks must use `\begin{frame}[fragile]`.
- Inside a `\note{...}` block, the characters `#`, `_`, `&`, and `$` are
  still active TeX. Either escape them (`\#`, `\_`, `\&`, `\$`) or
  rephrase to avoid them. They cause real but cryptic build errors.
- The Makefile's `notes` and `handout` targets pass a TeX prefix to
  `pdflatex` via the command line. If you change the build target,
  keep the prefix and `\input{...}` together inside one quoted argument.

## Status of the talk

- 38 slides (39 with the standout Q&A page).
- ~45 minutes at a normal speaking pace, leaving 15 for questions in
  a 60-minute slot.
- Speaker notes have anticipated questions for the Q&A.
- All three PDF variants build cleanly on TeX Live 2025.
