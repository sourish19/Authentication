class ApiResponse {
  constructor(statusCode, message = 'Successfull', data = []) {
    ((this.statusCode = statusCode),
      (this.message = message),
      (this.success = statusCode < 400),
      (this.data = data));
  }
}

export default ApiResponse;
