<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'
import type { BlogPost } from '../api/types'

const route = useRoute()
const auth = useAuthStore()
const post = ref<BlogPost | null>(null)
const commentText = ref('')
const loading = ref(true)

async function load() {
  loading.value = true
  const { data } = await api.get<BlogPost>(`/blog/${route.params.slug}`)
  post.value = data
  loading.value = false
}

async function addComment() {
  if (!commentText.value.trim() || !post.value) return
  await api.post(`/blog/${post.value.slug}/comments`, { content: commentText.value })
  commentText.value = ''
  await load()
}

async function deleteComment(id: number) {
  await api.delete(`/blog/comments/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div class="max-w-3xl mx-auto px-4 py-10">
    <div v-if="loading" class="bento-card p-12 text-center text-gray-500">Loading...</div>

    <article v-else-if="post">
      <div class="bento-card p-8 mb-6">
        <router-link to="/blog" class="text-sm text-red-700 hover:underline mb-4 inline-block">&larr; Back to blog</router-link>
        <img v-if="post.cover_url" :src="post.cover_url" :alt="post.title" class="w-full rounded-xl mb-6 max-h-72 object-cover" />
        <h1 class="text-3xl font-bold mb-2">{{ post.title }}</h1>
        <time class="text-sm text-gray-500">{{ new Date(post.created_at).toLocaleDateString() }}</time>
        <div class="prose prose-invert mt-8 max-w-none text-gray-300 leading-relaxed" v-html="post.content"></div>
      </div>

      <div class="bento-card p-6">
        <h2 class="text-lg font-semibold mb-4">Comments ({{ post.comments?.length || 0 }})</h2>

        <form v-if="auth.isLoggedIn" @submit.prevent="addComment" class="mb-6">
          <textarea v-model="commentText" rows="3" placeholder="Write a comment..."
            class="input resize-none"></textarea>
          <button type="submit" class="btn mt-2">Post</button>
        </form>
        <p v-else class="text-gray-500 text-sm mb-6">
          <router-link to="/login" class="text-red-700 hover:underline">Log in</router-link> to comment.
        </p>

        <div class="space-y-3">
          <div v-for="comment in post.comments" :key="comment.id"
            class="bg-gray-800/40 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="font-medium text-sm">{{ comment.user.username }}</span>
              <div class="flex items-center gap-3">
                <time class="text-xs text-gray-600">{{ new Date(comment.created_at).toLocaleDateString() }}</time>
                <button v-if="auth.user?.id === comment.user_id || auth.isAdmin"
                  @click="deleteComment(comment.id)" class="text-xs text-red-600/60 hover:text-red-600">Delete</button>
              </div>
            </div>
            <p class="text-sm text-gray-400">{{ comment.content }}</p>
          </div>
        </div>
      </div>
    </article>
  </div>
</template>
