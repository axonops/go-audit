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

func queryOrders(db *sql.DB) ([]Order, error) {
	rows, err := db.Query("SELECT id, user_id, item_id, quantity, status, created_at, updated_at FROM orders ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("query orders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var orders []Order
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.UserID, &o.ItemID, &o.Quantity, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan order: %w", err)
		}
		orders = append(orders, o)
	}
	if orders == nil {
		orders = []Order{}
	}
	return orders, rows.Err()
}

func queryOrder(db *sql.DB, id string) (*Order, error) {
	var o Order
	err := db.QueryRow(
		"SELECT id, user_id, item_id, quantity, status, created_at, updated_at FROM orders WHERE id = $1", id,
	).Scan(&o.ID, &o.UserID, &o.ItemID, &o.Quantity, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("query order %s: %w", id, err)
	}
	return &o, nil
}

func insertOrder(db *sql.DB, id, userID, itemID string, quantity int) (*Order, error) {
	var o Order
	err := db.QueryRow(
		"INSERT INTO orders (id, user_id, item_id, quantity) VALUES ($1, $2, $3, $4) RETURNING id, user_id, item_id, quantity, status, created_at, updated_at",
		id, userID, itemID, quantity,
	).Scan(&o.ID, &o.UserID, &o.ItemID, &o.Quantity, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert order: %w", err)
	}
	return &o, nil
}

func updateOrderDB(db *sql.DB, id, status string) (*Order, error) {
	var o Order
	err := db.QueryRow(
		"UPDATE orders SET status = $2, updated_at = NOW() WHERE id = $1 RETURNING id, user_id, item_id, quantity, status, created_at, updated_at",
		id, status,
	).Scan(&o.ID, &o.UserID, &o.ItemID, &o.Quantity, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update order %s: %w", id, err)
	}
	return &o, nil
}
