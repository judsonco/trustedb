#!/usr/bin/env bats

@test "init" {
  result="$(echo 2+2 | bc)"
  [ "$result" -eq 4 ]
}
