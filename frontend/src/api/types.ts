export interface User {
  id: number
  username: string
  email?: string
  first_name?: string
  last_name?: string
  profile_picture?: string
  telegram_id?: string
  vk_id?: string
  provider?: string
  is_admin: boolean
  created_at: string
}

export interface BlogPost {
  id: number
  title: string
  slug: string
  content: string
  summary?: string
  cover_url?: string
  published: boolean
  created_at: string
  updated_at: string
  comments?: Comment[]
}

export interface Comment {
  id: number
  post_id: number
  user_id: number
  content: string
  created_at: string
  user: User
}

export interface MusicRelease {
  id: number
  title: string
  artist?: string
  cover_url?: string
  release_url?: string
  embed_url?: string
  release_date?: string
  sort_order: number
}

export interface MusicDemo {
  id: number
  title: string
  description?: string
  file_url?: string
  embed_url?: string
  sort_order: number
}

export interface RadioStream {
  id: number
  title: string
  stream_url: string
  is_active: boolean
}

export interface Project {
  id: number
  title: string
  description?: string
  image_url?: string
  project_url?: string
  sort_order: number
}

export interface NavigationLink {
  id: number
  title: string
  url: string
  icon?: string
  sort_order: number
  is_active: boolean
}

export interface PaginatedResponse<T> {
  posts: T[]
  total: number
  page: number
  limit: number
}

export type ApartmentStatus = 'new' | 'scheduled' | 'visited' | 'shortlist' | 'rejected'
export type ApartmentSource = 'cian' | 'yandex' | 'avito' | 'domclick' | 'other'

export interface ApartmentCriterion {
  id: number
  key: string
  label_en: string
  label_ru: string
  weight: number
  sort_order: number
  is_active: boolean
}

export interface ApartmentRating {
  id: number
  apartment_id: number
  user_id: number
  scores: Record<string, number>
  comment?: string
  score: number
  user?: User
  created_at: string
  updated_at: string
}

export interface Apartment {
  id: number
  url: string
  source: ApartmentSource
  title: string
  address?: string
  price: number
  rooms: number
  area: number
  floor: number
  total_floors: number
  notes?: string
  status: ApartmentStatus
  created_by: number
  created_at: string
  updated_at: string
  creator?: User
  ratings: ApartmentRating[]
  score: number
}

export interface AdminUser extends User {
  is_banned: boolean
  updated_at: string
}
