# syntax=docker/dockerfile:1
# Dashboard. Placeholder static page until build step 18 replaces it with the React app.
FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY frontend/placeholder/ /usr/share/nginx/html/
EXPOSE 8080
