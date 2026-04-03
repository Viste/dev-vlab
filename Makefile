.PHONY: dev-backend dev-frontend docker-build docker-push

dev-backend:
	cd backend && go run ./cmd/api

dev-frontend:
	cd frontend && npm run dev

docker-build:
	docker build -t vistee/vlab:vsite .

docker-push: docker-build
	docker push vistee/vlab:vsite
