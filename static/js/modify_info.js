$('#search_id').click(function () {

                $.ajax({

                    url: "",

                    type: "POST",

                    data: $('#ID').serialize(),



                    success: function (data) {
                        $("#info tr:not(:first)").empty(); //清空table（除了第一行以外）
                                                console.log("execute modify_info.js");

                        var rownum = 0;
                        //var rownum=$("#table1 tr").length-2;

                        for (var i = 0; i < data.length; i++) {

                            rownum = i;  // 第一行是表头
                            var num = i + 1;

                            var staffName = data[i][0];

                            var staffPhone = data[i][1];

                            var staffProfile = data[i][2];

                            var row = "<tr><td>" + num + "</td><td>" + staffName + "</td><td>" + staffPhone + "</td><td>" + staffProfile + "</td></tr>";


                            $(row).insertAfter($("#info tr:eq(" + rownum + ")"));}

                    }

                });

            })
