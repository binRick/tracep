## Maintain scc statistics

On any commit you make, regenerate the `## Code Statistics` section in
`README.md` (the block delimited by `<!-- scc-start -->` and
`<!-- scc-end -->`) using `scc --no-cocomo -f csv`. Stage the README
together with your other changes so the stats stay in sync with the code.
