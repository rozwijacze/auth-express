const BASE_ROUTE = '/api';
const AUTH_ROUTE = `${BASE_ROUTE}/auth`;
const USERS_ROUTE = `${BASE_ROUTE}/users`;

const ROUTES = {
  BASE: BASE_ROUTE,
  AUTH: {
    BASE: AUTH_ROUTE,
    LOGIN: `${AUTH_ROUTE}/login`,
    REGISTER: `${AUTH_ROUTE}/register`,
    REFRESH: `${AUTH_ROUTE}/refresh`,
    LOGOUT: `${AUTH_ROUTE}/logout`,
  },
  USERS: {
    BASE: USERS_ROUTE,
    PROFILE: `${USERS_ROUTE}/profile`,
    UPDATE: `${USERS_ROUTE}/update`,
  },
};

module.exports = ROUTES;
