// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pg

import (
	"database/sql"
	"fmt"
	"log"
)

func Createdb(dbname string) {
	connstr := "host=/var/run/postgresql dbname=postgres"
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s;", dbname))
	if err != nil {
		log.Fatalf("dropdb: %s", err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbname))
	if err != nil {
		log.Fatalf("createdb: %s", err)
	}
}

func Dropdb(dbname string) {
	connstr := "host=/var/run/postgresql dbname=postgres"
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("DROP DATABASE %s;", dbname))
	if err != nil {
		log.Fatalf("dropdb: %s", err)
	}
}
