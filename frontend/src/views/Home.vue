<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import type { Project, NavigationLink } from '../api/types'

const projects = ref<Project[]>([])
const links = ref<NavigationLink[]>([])

onMounted(async () => {
  const [projRes, linkRes] = await Promise.all([
    api.get<Project[]>('/projects').catch(() => ({ data: [] })),
    api.get<NavigationLink[]>('/nav-links').catch(() => ({ data: [] })),
  ])
  projects.value = projRes.data
  links.value = linkRes.data
})

const skills = [
  { label: 'SRE', color: 'text-emerald-400 bg-emerald-400/10' },
  { label: 'Go', color: 'text-cyan-400 bg-cyan-400/10' },
  { label: 'Python', color: 'text-amber-400 bg-amber-400/10' },
  { label: 'C/C++', color: 'text-blue-400 bg-blue-400/10' },
  { label: 'Kubernetes', color: 'text-blue-400 bg-blue-400/10' },
  { label: 'DevOps', color: 'text-purple-400 bg-purple-400/10' },
  { label: 'D&B', color: 'text-red-400 bg-red-400/10' },
  { label: 'Hip-Hop', color: 'text-red-400 bg-red-400/10' },
]
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 py-10">
    <div class="grid grid-cols-1 md:grid-cols-12 gap-4">

      <!-- Hero -->
      <div class="md:col-span-8 card-dark p-8 md:p-10 relative overflow-hidden">
        <div class="absolute top-0 right-0 w-64 h-64 bg-red-500/5 rounded-full blur-3xl -mr-20 -mt-20"></div>
        <div class="relative">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-xs font-mono mb-6">
            <span class="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
            hello world;
          </div>
          <h1 class="text-4xl md:text-5xl font-bold leading-[1.1] mb-5">
            Site Reliability<br/>Engineer.
            <span class="text-red-500">Music<br/>Producer.</span>
          </h1>
          <p class="text-gray-400 text-base max-w-lg leading-relaxed">
            Building and maintaining infrastructure, CI/CD pipelines, and keeping things alive in production.
            Writing Go, Python, and C/C++ when needed. Making drum &amp; bass and hip-hop beats in spare time.
          </p>
        </div>
      </div>

      <!-- Get in touch -->
      <div class="md:col-span-4 card-dark p-6 flex flex-col justify-between">
        <div>
          <div class="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center mb-4">
            <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
            </svg>
          </div>
          <h2 class="text-lg font-bold mb-1">Get in touch</h2>
          <p class="text-gray-500 text-sm">Collaborate or just say hi</p>
        </div>
        <div class="mt-6 space-y-1.5">
          <a v-for="link in links" :key="link.id" :href="link.url" target="_blank"
            class="flex items-center justify-between px-3 py-2 rounded-xl text-sm text-gray-300 hover:bg-white/5 transition group">
            <span>{{ link.title }}</span>
            <svg class="w-3.5 h-3.5 text-gray-600 group-hover:text-red-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
          <a href="https://t.me/vistee" target="_blank"
            class="flex items-center justify-between px-3 py-2 rounded-xl text-sm text-gray-300 hover:bg-white/5 transition group">
            <span>Telegram</span>
            <svg class="w-3.5 h-3.5 text-gray-600 group-hover:text-red-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
          <a href="https://t.me/redmadn" target="_blank"
            class="flex items-center justify-between px-3 py-2 rounded-xl text-sm text-gray-300 hover:bg-white/5 transition group">
            <span>Misc &amp; Demos</span>
            <svg class="w-3.5 h-3.5 text-gray-600 group-hover:text-red-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
          <a href="https://t.me/stalinfollower" target="_blank"
            class="flex items-center justify-between px-3 py-2 rounded-xl text-sm text-gray-300 hover:bg-white/5 transition group">
            <span>Memes</span>
            <svg class="w-3.5 h-3.5 text-gray-600 group-hover:text-red-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </div>
      </div>

      <!-- Skills -->
      <div class="md:col-span-12 card-dark p-6">
        <div class="flex flex-wrap gap-2">
          <span v-for="skill in skills" :key="skill.label"
            class="px-3.5 py-1.5 rounded-xl text-xs font-medium" :class="skill.color">
            {{ skill.label }}
          </span>
        </div>
      </div>

      <!-- Music -->
      <div class="md:col-span-4 card-dark p-6 cursor-pointer group" @click="$router.push('/music')">
        <div class="w-10 h-10 rounded-xl bg-emerald-400/10 flex items-center justify-center mb-4">
          <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2z" />
          </svg>
        </div>
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-lg font-bold mb-1">Music &amp; Sound</h2>
            <p class="text-gray-500 text-sm">Releases, demos, radio</p>
          </div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-emerald-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
      </div>

      <!-- Blog -->
      <div class="md:col-span-4 card-dark p-6 cursor-pointer group" @click="$router.push('/blog')">
        <div class="w-10 h-10 rounded-xl bg-blue-400/10 flex items-center justify-center mb-4">
          <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z" />
          </svg>
        </div>
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-lg font-bold mb-1">Blog</h2>
            <p class="text-gray-500 text-sm">Tech, music, and life</p>
          </div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-blue-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
      </div>

      <!-- GitHub -->
      <div class="md:col-span-4 card-dark p-6 group">
        <div class="w-10 h-10 rounded-xl bg-purple-400/10 flex items-center justify-center mb-4">
          <svg class="w-5 h-5 text-purple-400" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
        </div>
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-lg font-bold mb-1">Open Source</h2>
            <p class="text-gray-500 text-sm">Check out my work</p>
          </div>
          <a href="https://github.com/Viste" target="_blank"
            class="px-3 py-1.5 rounded-lg bg-white/5 text-xs text-gray-300 hover:bg-white/10 transition">
            GitHub &rarr;
          </a>
        </div>
      </div>

      <!-- Projects -->
      <div v-if="projects.length" class="md:col-span-12 card-dark p-6">
        <div class="flex items-center gap-3 mb-5">
          <div class="w-8 h-8 rounded-lg bg-amber-400/10 flex items-center justify-center">
            <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6z" />
            </svg>
          </div>
          <h2 class="text-lg font-bold">Projects</h2>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <a v-for="project in projects" :key="project.id"
            :href="project.project_url" target="_blank"
            class="group flex gap-4 p-4 rounded-xl bg-white/[0.02] hover:bg-white/[0.05] transition border border-gray-800/30 hover:border-gray-700/50">
            <img v-if="project.image_url" :src="project.image_url" :alt="project.title"
              class="w-11 h-11 rounded-lg object-cover shrink-0" />
            <div class="min-w-0">
              <h3 class="font-semibold text-sm group-hover:text-red-400 transition truncate">{{ project.title }}</h3>
              <p v-if="project.description" class="text-xs text-gray-500 mt-0.5 line-clamp-2">{{ project.description }}</p>
            </div>
          </a>
        </div>
      </div>

    </div>
  </div>
</template>
