#!/usr/bin/env bats

setup() {
  TRUSTEDB_BINARY="$BATS_TEST_DIRNAME/../bin/trustedb"
  KEYFILE_1=$BATS_TMPDIR/Keyfile_1
  KEYFILE_2=$BATS_TMPDIR/Keyfile_2
  TRUSTEDB_TRUSTFILE=$BATS_TMPDIR/Trustfile
}

teardown() {
  rm -rf "$KEYFILE_1"
  rm -rf "$KEYFILE_2"
}

@test "init" {
  # Make sure the location is clean
  rm -rf "$TRUSTEDB_TRUSTFILE"

  run $TRUSTEDB_BINARY init
  [ "$status" -eq 0 ]
}

@test "create" {
  TRUSTEDB_KEYFILE=$KEYFILE_1
  run $TRUSTEDB_BINARY init
  [ "$status" -eq 0 ]
  [ -f "$TRUSTEDB_TRUSTFILE" ]

  run $TRUSTEDB_BINARY identity create
  [ "$status" -eq 0 ]
  [ -f "$TRUSTEDB_KEYFILE" ]
}

@test "request addition" {
  TRUSTEDB_KEYFILE=$KEYFILE_1
  run $TRUSTEDB_BINARY init
  [ "$status" -eq 0 ]

  run $TRUSTEDB_BINARY identity create
  [ "$status" -eq 0 ]

  run $TRUSTEDB_BINARY request addition --identifier="test@test.com"
  [ "$status" -eq 0 ]
  [ $(cat $TRUSTEDB_TRUSTFILE | grep test) ]
}

@test "approve addition" {
  TRUSTEDB_KEYFILE=$KEYFILE_1
  run $TRUSTEDB_BINARY init
  [ "$status" -eq 0 ]

  run $TRUSTEDB_BINARY create-key
  [ "$status" -eq 0 ]

  run $TRUSTEDB_BINARY request addition --identifier="test@test.com"
  [ "$status" -eq 0 ]
  [ $(cat $TRUSTEDB_TRUSTFILE | grep test) ]
}
