function Register_Button(arg) {
    
    if(arg == 1)//登陆 admin admin
    {
        //获取 id="usr"的数据
        var usr = document.getElementById("usr").value;
        var pwd = document.getElementById("pwd").value;
        if(usr=="admin" && pwd =="admin")
        {
            window.location.href = "http://www.baidu.com"
        }
        else
        {
            alert("用户名或密码错误请重新输入");
            document.getElementById("usr").value="";
            document.getElementById("pwd").value="";
        }
        
    }
    else if(arg == 0)//取消
    {
        document.getElementById("usr").value="";
        document.getElementById("pwd").value="";
    }
   
}

  //回车时，默认是登陆
 function on_return(){
 if(window.event.keyCode == 13){
  if (document.all('Register')!=null){
   document.all('Register').click();
   }
 }
 }