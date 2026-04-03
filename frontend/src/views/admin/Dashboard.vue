<script setup lang="ts">
import { useAuthStore } from '../../stores/auth'
const auth = useAuthStore()
</script>

<template>
  <div>
    <div class="bento-card p-8 mb-6">
      <p class="text-sm text-red-700 font-mono mb-2">admin</p>
      <h1 class="text-2xl font-bold">Dashboard</h1>
      <p class="text-gray-400 mt-1">Welcome back, {{ auth.user?.username }}.</p>
    </div>

    <div class="grid md:grid-cols-3 gap-3">
      <router-link to="/admin/blog" class="admin-card p-5">
        <h3 class="font-semibold">Blog Posts</h3>
        <p class="text-sm text-gray-500 mt-1">Manage blog content</p>
      </router-link>
      <router-link to="/admin/releases" class="admin-card p-5">
        <h3 class="font-semibold">Releases</h3>
        <p class="text-sm text-gray-500 mt-1">Music releases</p>
      </router-link>
      <router-link to="/admin/demos" class="admin-card p-5">
        <h3 class="font-semibold">Demos</h3>
        <p class="text-sm text-gray-500 mt-1">Music demos</p>
      </router-link>
      <router-link to="/admin/radio" class="admin-card p-5">
        <h3 class="font-semibold">Radio</h3>
        <p class="text-sm text-gray-500 mt-1">Radio streams</p>
      </router-link>
      <router-link to="/admin/projects" class="admin-card p-5">
        <h3 class="font-semibold">Projects</h3>
        <p class="text-sm text-gray-500 mt-1">Portfolio projects</p>
      </router-link>
      <router-link to="/admin/nav-links" class="admin-card p-5">
        <h3 class="font-semibold">Nav Links</h3>
        <p class="text-sm text-gray-500 mt-1">Navigation links</p>
      </router-link>
    </div>
  </div>
</template>
