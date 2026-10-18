<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../../api/client'
import { useAuthStore } from '../../stores/auth'
import type { AdminUser } from '../../api/types'
import { dateLocales, type Locale } from '../../i18n'

const auth = useAuthStore()
const { t, locale } = useI18n()

const users = ref<AdminUser[]>([])
const loading = ref(true)
const error = ref('')
const showForm = ref(false)
const saving = ref(false)
const createdNote = ref('')

const emptyForm = () => ({ username: '', password: '', first_name: '', last_name: '', email: '', is_admin: true })
const form = ref(emptyForm())

const resetFor = ref<number | null>(null)
const resetPassword = ref('')

async function load() {
  error.value = ''
  try {
    const { data } = await api.get<AdminUser[]>('/admin/users')
    users.value = data
  } catch (e: any) {
    error.value = e.response?.data?.error || t('users.loadFailed')
  } finally {
    loading.value = false
  }
}

function generatePassword() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = new Uint8Array(14)
  crypto.getRandomValues(bytes)
  form.value.password = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

async function create() {
  error.value = ''
  createdNote.value = ''
  saving.value = true
  try {
    const { data } = await api.post<AdminUser>('/admin/users', form.value)
    createdNote.value = t('users.created', { username: data.username, password: form.value.password })
    form.value = emptyForm()
    showForm.value = false
    await load()
  } catch (e: any) {
    error.value = e.response?.data?.error || t('users.createFailed')
  } finally {
    saving.value = false
  }
}

async function patch(u: AdminUser, body: Record<string, unknown>) {
  error.value = ''
  try {
    const { data } = await api.put<AdminUser>(`/admin/users/${u.id}`, body)
    const idx = users.value.findIndex((x) => x.id === u.id)
    if (idx >= 0) users.value[idx] = data
    if (u.id === auth.user?.id) await auth.fetchUser()
  } catch (e: any) {
    error.value = e.response?.data?.error || t('users.updateFailed')
  }
}

async function applyReset(u: AdminUser) {
  if (resetPassword.value.length < 6) {
    error.value = t('users.minPassword')
    return
  }
  await patch(u, { password: resetPassword.value })
  if (!error.value) {
    createdNote.value = t('users.passwordSet', { username: u.username, password: resetPassword.value })
    resetFor.value = null
    resetPassword.value = ''
  }
}

async function remove(u: AdminUser) {
  if (!confirm(t('users.confirmDelete', { username: u.username }))) return
  error.value = ''
  try {
    await api.delete(`/admin/users/${u.id}`)
    users.value = users.value.filter((x) => x.id !== u.id)
  } catch (e: any) {
    error.value = e.response?.data?.error || t('users.deleteFailed')
  }
}

function formatDate(s: string) {
  return new Date(s).toLocaleDateString(dateLocales[locale.value as Locale])
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6 gap-4 flex-wrap">
      <div>
        <h1 class="text-xl font-bold">{{ $t('users.title') }}</h1>
        <p class="text-gray-500 text-sm mt-0.5">{{ $t('users.subtitle') }}</p>
      </div>
      <button @click="showForm = !showForm" class="btn">{{ showForm ? $t('common.close') : $t('users.newUser') }}</button>
    </div>

    <form v-if="showForm" @submit.prevent="create" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 mb-6 space-y-3">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label class="label">{{ $t('users.username') }}</label>
          <input v-model="form.username" class="input" required autocomplete="off" :placeholder="$t('users.usernameHint')" />
        </div>
        <div>
          <label class="label">{{ $t('users.password') }}</label>
          <div class="flex gap-2">
            <input v-model="form.password" class="input font-mono" required minlength="6" autocomplete="new-password" />
            <button type="button" @click="generatePassword" class="btn-secondary shrink-0">{{ $t('users.generate') }}</button>
          </div>
        </div>
        <div>
          <label class="label">{{ $t('users.firstName') }}</label>
          <input v-model="form.first_name" class="input" />
        </div>
        <div>
          <label class="label">{{ $t('users.lastName') }}</label>
          <input v-model="form.last_name" class="input" />
        </div>
        <div>
          <label class="label">{{ $t('users.email') }}</label>
          <input v-model="form.email" type="email" class="input" />
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-300 self-end pb-2.5 cursor-pointer select-none">
          <input v-model="form.is_admin" type="checkbox" class="accent-red-600" />
          {{ $t('users.admin') }}
        </label>
      </div>
      <div class="flex gap-2 pt-1">
        <button type="submit" class="btn" :disabled="saving">{{ saving ? $t('users.creating') : $t('users.create') }}</button>
        <button type="button" @click="showForm = false" class="btn-secondary">{{ $t('common.cancel') }}</button>
      </div>
    </form>

    <p v-if="createdNote" class="text-sm text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-3 mb-4 font-mono break-all">{{ createdNote }}</p>
    <p v-if="error" class="text-sm text-red-500 mb-4">{{ error }}</p>

    <div v-if="loading" class="text-sm text-gray-500 py-10 text-center">{{ $t('common.loading') }}</div>
    <div v-else class="space-y-2">
      <div v-for="u in users" :key="u.id" class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-4">
        <div class="flex items-center gap-4">
          <img v-if="u.profile_picture" :src="u.profile_picture" class="w-10 h-10 rounded-xl object-cover shrink-0" />
          <div v-else class="w-10 h-10 rounded-xl bg-gray-800 flex items-center justify-center text-sm font-bold text-red-400 shrink-0">
            {{ u.username[0]?.toUpperCase() }}
          </div>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-medium">{{ u.username }}</span>
              <span v-if="u.id === auth.user?.id" class="text-[10px] text-gray-600">{{ $t('users.you') }}</span>
              <span class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-white/5 text-gray-500">{{ u.provider || 'local' }}</span>
              <span v-if="u.is_admin" class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">{{ $t('users.adminBadge') }}</span>
              <span v-if="u.is_banned" class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400">{{ $t('users.bannedBadge') }}</span>
            </div>
            <div class="text-xs text-gray-500 mt-0.5 truncate">
              {{ [u.first_name, u.last_name].filter(Boolean).join(' ') || '—' }}
              <span v-if="u.email"> · {{ u.email }}</span>
              · {{ $t('users.joined', { date: formatDate(u.created_at) }) }}
            </div>
          </div>
          <div class="flex gap-2 shrink-0 flex-wrap justify-end">
            <button @click="patch(u, { is_admin: !u.is_admin })" class="btn-sm" :disabled="u.id === auth.user?.id">{{ u.is_admin ? $t('users.revokeAdmin') : $t('users.makeAdmin') }}</button>
            <button @click="resetFor = resetFor === u.id ? null : u.id; resetPassword = ''" class="btn-sm">{{ $t('users.passwordButton') }}</button>
            <button @click="patch(u, { is_banned: !u.is_banned })" class="btn-sm" :disabled="u.id === auth.user?.id">{{ u.is_banned ? $t('users.unban') : $t('users.ban') }}</button>
            <button @click="remove(u)" class="btn-sm-danger" :disabled="u.id === auth.user?.id">{{ $t('common.delete') }}</button>
          </div>
        </div>
        <form v-if="resetFor === u.id" @submit.prevent="applyReset(u)" class="flex items-center gap-2 mt-3 pt-3 border-t border-gray-800/40">
          <input v-model="resetPassword" class="input font-mono flex-1" :placeholder="$t('users.newPassword')" autocomplete="new-password" />
          <button type="submit" class="btn shrink-0">{{ $t('users.setPassword') }}</button>
          <button type="button" @click="resetFor = null" class="btn-secondary shrink-0">{{ $t('common.cancel') }}</button>
        </form>
      </div>
    </div>
  </div>
</template>
