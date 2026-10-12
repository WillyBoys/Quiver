"""Agent runtime built on the Claude Agent SDK.

Runs in its own container so the Claude credential never sits in the worker. Built-in
tools are disabled; the agent's only tools are Quiver's, served by the worker over MCP.
"""
