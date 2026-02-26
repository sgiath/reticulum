[
  tools: [
    {:compiler, true},
    {:formatter, true},
    {:unused_deps, true},
    {:credo, true},
    {:markdown,
     command: "prettier **/*.md --log-level warn",
     fix: "prettier **/*.md --write --log-level warn"},
    {:ex_unit, true}
  ]
]
