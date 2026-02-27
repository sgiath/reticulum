This is library implementing Reticulum protocol in Elixir

## Submodules

`./Reticulum/` submodule serves as read-only reference for Reticulim protocol implementation. This library is the source of truth for correct protocol behavior
`./lxmf/` submodule serves as read-only reference for LXMF protocol implementation. This library is the source of truth for correct protocol behavior

`./reticulum_ex/` submodule serves as read-only reference of different Elixir reticulum library. This is not state of the art or reference but can contain useful patterns we can draw inspiration from and inform our decisions

## Verification

You must run `mix check` and fix any issues it reports before declaring any coding task as finished

## No backwards compatibility

This app has no users yet, there's no real data yet. Make whatever changes you want and don't worry about data migration or backward compatibility. We will figure it out when we actually ship.

This project is super green-field, it is OK if you change the schema or patterns entirely.
