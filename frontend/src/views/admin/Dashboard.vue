<script setup lang="ts">
import { useAuthStore } from '../../stores/auth'
const auth = useAuthStore()
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold mb-4">Admin Dashboard</h1>
    <p class="text-gray-400">Welcome back, {{ auth.user?.username }}.</p>

    <div class="grid md:grid-cols-3 gap-4 mt-8">
      <router-link to="/admin/blog" class="admin-card">
        <h3 class="font-semibold">Blog Posts</h3>
        <p class="text-sm text-gray-400">Manage blog content</p>
      </router-link>
      <router-link to="/admin/releases" class="admin-card">
        <h3 class="font-semibold">Releases</h3>
        <p class="text-sm text-gray-400">Music releases</p>
      </router-link>
      <router-link to="/admin/demos" class="admin-card">
        <h3 class="font-semibold">Demos</h3>
        <p class="text-sm text-gray-400">Music demos</p>
      </router-link>
      <router-link to="/admin/radio" class="admin-card">
        <h3 class="font-semibold">Radio</h3>
        <p class="text-sm text-gray-400">Radio streams</p>
      </router-link>
      <router-link to="/admin/projects" class="admin-card">
        <h3 class="font-semibold">Projects</h3>
        <p class="text-sm text-gray-400">Portfolio projects</p>
      </router-link>
      <router-link to="/admin/nav-links" class="admin-card">
        <h3 class="font-semibold">Nav Links</h3>
        <p class="text-sm text-gray-400">Navigation links</p>
      </router-link>
    </div>
  </div>
</template>
