<div class="col-md-12" id="{{ $options['sectionId'] }}-container">

    <div class="container" id="{{ $options['sectionId'] }}">

        <div class="row">
            <div class="col-lg-12 text-center"><h1>Contact us</h1></div>
        </div>

        <form class="form-horizontal" action="/contact" method="post">
        <div class="row">
            <div class="col-lg-6">
                <div class="form-group">
                    <div class="col-sm-12">
                        <textarea class="form-control" name="message" id="message" placeholder="Message" style="height: 133px;"></textarea>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="form-group">
                    <div class="col-sm-12">
                        <input type="text" name="name" class="form-control" id="name" placeholder="Name">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-12">
                        <input type="email" name="email" class="form-control" id="email" placeholder="Email">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-9">
                        <input type="text" name="telephone" class="form-control" id="telephone" placeholder="Telephone">
                    </div>

                    <div class="clearfix extraPad hidden-sm hidden-md hidden-lg"></div>

                    <div class="col-sm-3">
                        <input class="btn btn-contact btn-block" type="submit" value="Submit">
                    </div>
                </div>
            </div>

        </div>
        <div class="row">
            <div class="col-lg-6">
                <div id="map"></div>
            </div>
            <div class="clearfix extraPad hidden-md hidden-lg"></div>
            <div class="col-lg-6">
                <div class="row hidden-md hidden-sm hidden-xs">
                    <div class="col-sm-12"><img src="/img/weheartleads.png" width="100%"></div>
                </div>
                <div class="clearfix extraPad hidden-sm hidden-lg hidden-xs"></div>
                <div class="row addressText">
                    <div class="col-sm-7">ChooseLeads Ltd. Base Point Swindon,<br />Rivermead, West Lea, Swindon, SN5 7EX.</div>
                    <div class="col-sm-5">01793 60 88 34<br /><a href="mailto:data.lovers@chooseleads.co.uk">data.lovers@chooseleads.co.uk</a></div>
                </div>
                <div class="row" style="padding-top: 10px; color: RGBA(255,255,255,0.5)">
                    <div class="col-sm-12 text-center"><b>Registered Address:</b> Studio GC 36-37 Warple Way, London, W3 0RG</div>
                </div>
            </div>
        </div>

        </form>

    </div>

</div>
