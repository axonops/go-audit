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

func queryItems(db *sql.DB) ([]Item, error) {
	rows, err := db.Query("SELECT id, name, description, created_at, updated_at FROM items ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("query items: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, it)
	}
	if items == nil {
		items = []Item{}
	}
	return items, rows.Err()
}

func queryItem(db *sql.DB, id string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"SELECT id, name, description, created_at, updated_at FROM items WHERE id = $1", id,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("query item %s: %w", id, err)
	}
	return &it, nil
}

func insertItem(db *sql.DB, id, name, description string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"INSERT INTO items (id, name, description) VALUES ($1, $2, $3) RETURNING id, name, description, created_at, updated_at",
		id, name, description,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert item: %w", err)
	}
	return &it, nil
}

func updateItemDB(db *sql.DB, id, name, description string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"UPDATE items SET name = $2, description = $3, updated_at = NOW() WHERE id = $1 RETURNING id, name, description, created_at, updated_at",
		id, name, description,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update item %s: %w", id, err)
	}
	return &it, nil
}

func deleteItemDB(db *sql.DB, id string) error {
	result, err := db.Exec("DELETE FROM items WHERE id = $1", id)
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
