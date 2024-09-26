const BASE_ROUTE = '/api';
const AUTH_ROUTE = `${BASE_ROUTE}/auth`;
const USER_ROUTE = `${BASE_ROUTE}/users`;

const ROUTES = {
  BASE: BASE_ROUTE,
  AUTH: {
    BASE: AUTH_ROUTE,
    LOGIN: `${AUTH_ROUTE}/login`,
    REGISTER: `${AUTH_ROUTE}/register`,
    REFRESH: `${AUTH_ROUTE}/refresh`,
    LOGOUT: `${AUTH_ROUTE}/logout`,
  },
  USER: {
    BASE: USER_ROUTE,
    PROFILE: `${USER_ROUTE}/profile`,
    UPDATE: `${USER_ROUTE}/update`,
  }
};

module.exports = ROUTES;