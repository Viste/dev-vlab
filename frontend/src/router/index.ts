import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: () => import('../layouts/DefaultLayout.vue'),
      children: [
        { path: '', name: 'home', component: () => import('../views/Home.vue') },
        { path: 'blog', name: 'blog', component: () => import('../views/Blog.vue') },
        { path: 'blog/:slug', name: 'blog-post', component: () => import('../views/BlogPost.vue') },
        { path: 'music', name: 'music', component: () => import('../views/Music.vue') },
        { path: 'saturator', name: 'saturator', component: () => import('../views/Saturator.vue') },
        { path: 'login', name: 'login', component: () => import('../views/Login.vue') },
        { path: 'profile', name: 'profile', component: () => import('../views/Profile.vue'), meta: { auth: true } },
        { path: 'auth/vk/callback', name: 'vk-callback', component: () => import('../views/VKCallback.vue') },
        { path: 'auth/telegram/callback', name: 'tg-callback', component: () => import('../views/TelegramCallback.vue') },
      ],
    },
    {
      path: '/admin',
      component: () => import('../layouts/AdminLayout.vue'),
      meta: { auth: true, admin: true },
      children: [
        { path: '', name: 'admin-dashboard', component: () => import('../views/admin/Dashboard.vue') },
        { path: 'blog', name: 'admin-blog', component: () => import('../views/admin/BlogManager.vue') },
        { path: 'blog/new', name: 'admin-blog-new', component: () => import('../views/admin/BlogEditor.vue') },
        { path: 'blog/:id/edit', name: 'admin-blog-edit', component: () => import('../views/admin/BlogEditor.vue') },
        { path: 'releases', name: 'admin-releases', component: () => import('../views/admin/ReleasesManager.vue') },
        { path: 'demos', name: 'admin-demos', component: () => import('../views/admin/DemosManager.vue') },
        { path: 'radio', name: 'admin-radio', component: () => import('../views/admin/RadioManager.vue') },
        { path: 'projects', name: 'admin-projects', component: () => import('../views/admin/ProjectsManager.vue') },
        { path: 'nav-links', name: 'admin-nav-links', component: () => import('../views/admin/NavLinksManager.vue') },
      ],
    },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()

  if (auth.isLoggedIn && !auth.user) {
    await auth.fetchUser()
  }

  if (to.meta.auth && !auth.isLoggedIn) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.meta.admin && !auth.isAdmin) {
    return { name: 'home' }
  }
})

export default router
