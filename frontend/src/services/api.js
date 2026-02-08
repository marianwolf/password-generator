import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api/v1';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Request interceptor for adding auth token
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('accessToken');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        const sessionToken = localStorage.getItem('sessionToken');
        if (sessionToken) {
            config.headers['X-Session-Token'] = sessionToken;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Response interceptor for handling errors
api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        // If 401 and not already retrying, try to refresh token
        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;

            try {
                const refreshToken = localStorage.getItem('refreshToken');
                if (refreshToken) {
                    api.defaults.headers.common['Authorization'] = `Bearer ${refreshToken}`;
                    const response = await api.post('/auth/refresh');
                    const { access_token } = response.data;

                    localStorage.setItem('accessToken', access_token);
                    api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

                    originalRequest.headers.Authorization = `Bearer ${access_token}`;
                    return api(originalRequest);
                }
            } catch (refreshError) {
                // Refresh failed, clear auth and redirect to login
                localStorage.removeItem('accessToken');
                localStorage.removeItem('sessionToken');
                localStorage.removeItem('refreshToken');
                window.location.href = '/login';
                return Promise.reject(refreshError);
            }
        }

        return Promise.reject(error);
    }
);

// Password API
export const passwordApi = {
    list: (params = {}) => api.get('/passwords', { params }),
    get: (id) => api.get(`/passwords/${id}`),
    create: (data) => api.post('/passwords', data),
    update: (id, data) => api.put(`/passwords/${id}`, data),
    delete: (id) => api.delete(`/passwords/${id}`),
    toggleFavorite: (id) => api.post(`/passwords/${id}/favorite`)
};

// Generator API
export const generatorApi = {
    generate: (params = {}) => api.get('/generate-password', { params })
};

// Export API
export const exportApi = {
    export: () => api.get('/export'),
    import: (data) => api.post('/import', data)
};

// Audit API
export const auditApi = {
    getLogs: (params = {}) => api.get('/audit-logs', { params })
};

// Session API
export const sessionApi = {
    getSessions: () => api.get('/sessions'),
    revokeSession: (id) => api.delete(`/sessions/${id}`)
};

// Stats API
export const statsApi = {
    getStats: () => api.get('/stats')
};

// Profile API
export const profileApi = {
    getProfile: () => api.get('/auth/profile'),
    updateProfile: (data) => api.put('/auth/profile', data)
};

export default api;
