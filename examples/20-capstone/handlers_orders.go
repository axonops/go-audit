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
	"encoding/json"
	"net/http"

	"github.com/axonops/audit"
	"github.com/google/uuid"
)

func (h *handlers) listOrders(w http.ResponseWriter, r *http.Request) {
	orders, err := queryOrders(h.db)
	if err != nil {
		h.log.Error("db query failed", "op", "list_orders", "error", err)
		writeError(w, r, http.StatusInternalServerError, "list orders failed")
		return
	}
	h.log.Debug("orders listed", "count", len(orders))
	writeJSON(w, http.StatusOK, orders)
}

func (h *handlers) getOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	order, err := queryOrder(h.db, id)
	if err != nil {
		h.log.Warn("order not found", "id", id)
		writeError(w, r, http.StatusNotFound, "order not found")
		return
	}
	writeJSON(w, http.StatusOK, order)
}

func (h *handlers) createOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		ItemID   string `json:"item_id"`
		Quantity int    `json:"quantity"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.UserID == "" || req.ItemID == "" {
		writeError(w, r, http.StatusBadRequest, "user_id and item_id are required")
		return
	}
	if req.Quantity <= 0 {
		req.Quantity = 1 // default to 1 for convenience in the demo
	}

	id := uuid.New().String()
	order, err := insertOrder(h.db, id, req.UserID, req.ItemID, req.Quantity)
	if err != nil {
		h.log.Error("db insert failed", "op", "create_order", "error", err,
			"user_id", req.UserID, "item_id", req.ItemID)
		writeError(w, r, http.StatusBadRequest, "create order failed: check user_id and item_id exist")
		return
	}
	h.log.Info("order created", "id", id, "user_id", req.UserID, "item_id", req.ItemID)

	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}
	writeJSON(w, http.StatusCreated, order)
}

func (h *handlers) updateOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	var req struct {
		Status string `json:"status"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Status == "" {
		writeError(w, r, http.StatusBadRequest, "status is required")
		return
	}

	order, err := updateOrderDB(h.db, id, req.Status)
	if err != nil {
		h.log.Warn("order not found for update", "id", id)
		writeError(w, r, http.StatusNotFound, "order not found")
		return
	}
	h.log.Info("order status updated", "id", id, "status", req.Status)
	writeJSON(w, http.StatusOK, order)
}
