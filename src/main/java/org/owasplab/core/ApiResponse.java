package org.owasplab.core;

public class ApiResponse<T> {
    private boolean success;
    private String message;
    private T data;
    private ApiMeta meta;

    public ApiResponse() {}
    public ApiResponse(boolean success, String message, T data, ApiMeta meta) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.meta = meta;
    }

    public static <T> ApiResponse<T> ok(T data,ApiMeta meta){
        return new ApiResponse<T>(true,"ok",data,meta);
    }
    public static <T> ApiResponse<T> fail(String message,ApiMeta meta){
        return new ApiResponse<T>(false,message,null,meta);
    }

    /*** 失败响应也可携带 data（用于靶场教学：例如返回 debug.sql / debug.sqlTemplate）。*/
    public static <T> ApiResponse<T> fail(String message, T data, ApiMeta meta){
        return new ApiResponse<T>(false,message,data,meta);
    }

    public boolean isSuccess() {return success;}
    public void setSuccess(boolean success) {this.success = success;}

    public String getMessage() {return message;}
    public void setMessage(String message) {this.message = message;}

    public T getData() {return data;}
    public void setData(T data) {this.data = data;}

    public ApiMeta getMeta() {return meta;}
    public void setMeta(ApiMeta meta) {this.meta = meta;}

}
