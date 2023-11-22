// Copyright The OpenTelemetry Authors
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
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"time"

	"go.uber.org/zap"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// Server is Http server that exposes multiple endpoints.
type Server struct {
	rand *rand.Rand
}

var tracer = otel.Tracer("rolldice")

// NewServer creates a server struct after initialing rand.
func NewServer() *Server {
	rd := rand.New(rand.NewSource(time.Now().Unix()))
	return &Server{
		rand: rd,
	}
}

func (s *Server) innerFunction(ctx context.Context) {
	_, span := tracer.Start(ctx, "innerFunction")
	defer span.End()

	span.SetAttributes(attribute.String("inner.key", "inner.value"))
}

func (s *Server) rolldice(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "roll")
	defer span.End()
	n := s.rand.Intn(6) + 1

	rollValueAttr := attribute.Int("roll.value", n)
	piAttr := attribute.Float64("pi", math.Pi)

	s.innerFunction(ctx)

	strAttr := attribute.String("nice.key", "string value!")
	strAttr2 := attribute.String("nice.key2", "string value 2!")
	span.SetAttributes(rollValueAttr, piAttr, strAttr, strAttr2)

	logger.Info("rolldice called", zap.Int("dice", n))
	fmt.Fprintf(w, "%v", n)
}

var logger *zap.Logger

func setupHandler(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/rolldice", s.rolldice)
	return mux
}

func main() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Printf("error creating zap logger, error:%v", err)
		return
	}

	port := fmt.Sprintf(":%d", 8080)
	logger.Info("starting http server", zap.String("port", port))

	s := NewServer()
	mux := setupHandler(s)
	if err := http.ListenAndServe(port, mux); err != nil {
		logger.Error("error running server", zap.Error(err))
	}
}
