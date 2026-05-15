// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"database/sql"
	"fmt"
)

func queryUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query("SELECT id, username, email, phone, created_at, updated_at FROM users ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Phone, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if users == nil {
		users = []User{}
	}
	return users, rows.Err()
}

func queryUser(db *sql.DB, id string) (*User, error) {
	var u User
	err := db.QueryRow(
		"SELECT id, username, email, phone, created_at, updated_at FROM users WHERE id = $1", id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Phone, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("query user %s: %w", id, err)
	}
	return &u, nil
}

func insertUser(db *sql.DB, id, username, email, phone string) (*User, error) {
	var u User
	err := db.QueryRow(
		"INSERT INTO users (id, username, email, phone) VALUES ($1, $2, $3, $4) RETURNING id, username, email, phone, created_at, updated_at",
		id, username, email, phone,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Phone, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &u, nil
}

func updateUserDB(db *sql.DB, id, username, email, phone string) (*User, error) {
	var u User
	err := db.QueryRow(
		"UPDATE users SET username = $2, email = $3, phone = $4, updated_at = NOW() WHERE id = $1 RETURNING id, username, email, phone, created_at, updated_at",
		id, username, email, phone,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Phone, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update user %s: %w", id, err)
	}
	return &u, nil
}

func deleteUserDB(db *sql.DB, id string) error {
	result, err := db.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("rows affected: %w", rowsErr)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
