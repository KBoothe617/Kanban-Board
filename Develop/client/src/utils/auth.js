import { jwtDecode } from 'jwt-decode';
class AuthService {
    getProfile() {
        // TODO: return the decoded token
        return jwtDecode(this.getToken());
    }
    loggedIn() {
        // TODO: return a value that indicates if the user is logged in
        const token = this.getToken();
        return !!token && !this.isTokenExpired(token);
    }
    isTokenExpired(token) {
        // TODO: return a value that indicates if the token is expired
        try {
            const decoded = jwtDecode(token);
            if (decoded?.exp && decoded?.exp < Date.now() / 1000) {
                return true;
            }
        }
        catch (err) {
            return false;
        }
    }
    getToken() {
        // TODO: return the token
        const loggedUser = localStorage.getItem('id_token');
        return loggedUser ? loggedUser : '';
    }
    login(idToken) {
        // TODO: set the token to localStorage
        // TODO: redirect to the home page
        localStorage.setItem('id_token', idToken);
        window.location.assign('/');
    }
    logout() {
        // TODO: remove the token from localStorage
        // TODO: redirect to the login page
        localStorage.removeItem('id_token');
        window.location.assign('./Login');
    }
}
export default new AuthService();
