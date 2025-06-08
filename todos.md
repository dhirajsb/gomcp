# GoMCP Library Todo List

## High Priority

- [ ] Add automatic JSON schema generation for MCP tool parameters, resource schemas, and prompt arguments using jsonschema library
- [ ] Create CLI tool for MCP project scaffolding with templates and best practices
- [ ] Add hot reload development mode for automatic server restart on code changes
- [ ] Build interactive development dashboard web UI for testing tools and resources
- [ ] Implement multiple transport support (HTTP, WebSocket, Unix sockets, TCP)
- [ ] Add auto-generated API documentation with OpenAPI/Swagger integration
- [ ] Integrate Prometheus metrics with /metrics endpoint for comprehensive monitoring

## Medium Priority

- [ ] Add GitHub Actions CI/CD pipeline for automated testing on PRs and main branch
- [ ] Implement comprehensive code coverage tracking and reporting with minimum thresholds
- [ ] Create request/response logging middleware for debugging and monitoring
- [ ] Add health check endpoints for production readiness and monitoring
- [ ] Implement graceful shutdown with proper connection draining
- [ ] Add tool versioning support for backwards compatibility
- [ ] Implement built-in rate limiting per client and endpoint
- [ ] Create mock tool generator and test client utilities for integration testing
- [ ] Add environment-based configuration management for dev/staging/prod
- [ ] Implement middleware system for composable request/response processing
- [ ] Add circuit breaker pattern for resilience against cascade failures

## Low Priority

- [ ] Create performance metrics dashboard with built-in Prometheus endpoint