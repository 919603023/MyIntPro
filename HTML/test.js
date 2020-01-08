function Register_Button(arg) {
    
    if(arg == 1)//登陆 admin admin
    {
        //获取 id="usr"的数据
        var usr = document.getElementById("usr").value;
        var pwd = document.getElementById("pwd").value;
        if(usr=="admin" && pwd =="admin")
        {
            window.location.href = "Main.html"
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

//按键按下时的处理函数
 function AUTO_KeyClick(){
 if(window.event.keyCode == 13){
  if (document.all('Register')!=null){
   document.all('Register').click();
   }
 }
 }
//获取当前时间
 function Get_NowTime() {
    
    var date = new Date();

    Y = date.getFullYear() + '-';
    
    M = (date.getMonth()+1 < 10 ? '0'+(date.getMonth()+1) : date.getMonth()+1) + '-';
    
    D = date.getDate() + ' ';
    
    h = date.getHours() + ':';
    
    m = date.getMinutes() + ':';
    
    s = date.getSeconds(); 
    


    document.getElementById("date").innerHTML = Y+M+D+h+m+s;
}